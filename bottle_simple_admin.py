##############################
#
# Bottle Simple Admin - implements Admin class user interface
# for use with the Bottle framework.
#
# There is some refactoring from Minimus admin.
# must have either MontyDB (stand-alone) or PyMongo (to a MongoDB instance)
# if you expect it to do anything
#
# License - MIT License, no guarantees of suitability for your app
#
##################################
version = "0.0.2"

from bottle import Bottle, redirect, abort, request
from bottle import jinja2_template
from montydb import MontyClient, set_storage
import json
from pymongo import MongoClient
from bson import ObjectId

import os
from passlib.context import CryptContext

pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=30000
)

def encrypt_password(password):
    return pwd_context.encrypt(password)

def check_encrypted_password(password, hashed):
    return pwd_context.verify(password, hashed)

# hooks for database and app
_db = None
_app = None

def jsonify(myjson):
    """jsonify() - makes it JSON similar to flask
    (in Bottle you don't have to do anything)
    """
    return myjson

def url_for(named_route, **kwargs):
    """url_for('route_name', key1=val1, key2=val2, ...) - returns a decorated route
             this is defined in flask! Bottle simulates it
    """
    url = _app.get_url(named_route, **kwargs)
    return url

def render_template(file_name, **kwargs):
    """render_template(filename, key1=val1, key2=val2, ...) - render a Jinja2 template
    as well as provides a convenient template hook to make it compatible with flask
    adds support for the url_for() function
    """
    kwargs['url_for'] = url_for
    return jinja2_template(file_name, **kwargs)
    
    
class Admin:
    """
    Allow for CRUD of data in database
    TODO
	7. write up security documents.  Possibly combine with minimus_users module.
	8. document the hell out of this module, because I will forget it.
    """
    def __init__(self, app:Bottle, 
                 session,
                 url_prefix="/admin",
                 db_uri=None,
                 db_file='bottle.db',
                 admin_database='bottle_admin',
                 users_collection='bottle_users',
                 require_authentication=True,
                 ):
        """__init__() - initialize the administration area"""
        global _db, _app
        _app = app # global access to app
        
        self.app = app
        self.url_prefix = url_prefix
        self.users_collection = users_collection
        
        self.require_authentication = require_authentication
        self.session = session
            
        ### set up the database ###
        if db_uri:
            app.client = MongoClient(db_uri)
        else:
            set_storage(db_file)
            app.db_file = db_file
            app.client = MontyClient(db_file)
            
        app.db = app.client[admin_database]
        _db = app.db
        
        ### Add the routes ###
        app.route(path=url_prefix + '/login',
                  method=['GET', 'POST'],
                  callback=self.login,
                  name="admin_login")
        app.route(path=url_prefix + '/logout',
                  name="admin_logout",
                  callback=self.logout)
        ####
        app.route(path=url_prefix,
                  name="admin_view_all",
                  callback=self.view_all)
        app.route(path=url_prefix + '/view/<coll>',
                  name="admin_view_collection",
                  callback=self.view_collection)
        app.route(path=url_prefix + '/edit/<coll>/<id>',
                  name="admin_edit_fields",
                  callback=self.edit_fields,
                  method=['GET', 'POST'])
        app.route(path=url_prefix + '/edit_schema/<coll>/<id>',
                  name="admin_edit_schema",
                  callback=self.edit_schema)
        app.route(path=url_prefix + '/edit_raw/<coll>/<id>',
                  name="admin_edit_json",
                  callback=self.edit_json,
                  method=['GET', 'POST'])
        app.route(path=url_prefix + '/delete/<coll>',
                  name="admin_delete_collection",
                  callback=self.delete_collection_prompt,
                  method=['GET', 'POST'])
        app.route(path=url_prefix + '/delete/<coll>/<id>',
                  name="admin_delete_collection_item",
                  callback=self.delete_collection_item,
                  method=['GET', 'POST'])
        app.route(path=url_prefix + '/add/<coll>',
                  name="admin_add_collection_item",
                  callback=self.add_collection_item,
                  method=['GET', 'POST'])
        app.route(path=url_prefix + '/add',
                  name="admin_add_collection",
                  callback=self.add_mod_collection,
                  method=['GET', 'POST'])
        app.route(
            path=url_prefix + '/modify/<coll>',
            name="admin_mod_collection",
            callback=self.add_mod_collection,
            method=['GET', 'POST'],
        )
        
        
        
    def login(self, filename=None, next=None):
        """
        login() - simple login with bootstrap or a Jinja2 file of your choice
        """
        if filename is None:
            html = self.render_login()
        
        if request.method == 'POST':
            username = request.forms.get('username')
            password = request.forms.get('password')
            user = self.get_user(username)
            if self.authenticate(username, password):
                user['_id'] = str(user['_id'])
                self.login_user(user)
                next = 'admin_view_all' if next is None else next
                return redirect(url_for(next))
            
        # if no filename the render internal
        if filename is None:
            return html
        
        # render external login
        return render_template(filename)
    
    def login_user(self, user):
        """sets the Session"""
        self.session.connect()
        self.session.data['is_authenticated'] = True
        self.session.data['user'] = user
        self.session.save()
        
        
    def login_check(self):
        """
        login_check() - if require_authentication return user else None
        """
        if self.require_authentication:
            if self.session.data.get('is_authenticated'):
                return self.session.data['user']
            return None
        else:
            return True
        

    def logout(self, next=None):
        """
        logout() - a simple logout, redirects to '/' or a next
        """
        self.logout_user()
        next = next if next else '/'
        return redirect(next)
    
    
    def logout_user(self):
        """logout_user() - pops the user out of the session"""
        if 'is_authenticated' in self.session.data:
            self.session.data['is_authenticated'] = False
        if 'user' in self.session.data:   
            self.session.data.pop('user')
    
    
    def view_all(self):
        """
        view_all() - view all collections in the database
        """
        if not self.login_check():
            return redirect(self.app.get_url('admin_login'))
        collections = self.app.db.list_collection_names()
        return render_template('admin/view_all.html', collections=collections )
    
    
    def view_collection(self, coll):
        """
        view_collection('collectionName') - view a specific collection in the database
        """
        if not self.login_check():
            return redirect(self.app.get_url('admin_login'))        
        data = list(self.app.db[coll].find())
        schema = self.app.db['_meta'].find_one({'name':coll})
        for doc in data:
            doc['_id'] = str(doc['_id'])
        return render_template('admin/view_collection.html', coll=coll, data=data, schema=schema)


    def edit_fields(self, coll, id):
        """
        edit_fields('collectionName', id) - render a specific record as fields
		** combine with edit_schema() during refactor
		"""
        if not self.login_check():
            return abort(401)        
        try:
            key = {'_id': ObjectId(id)}
        except Exception as e:
            return jsonify({'status': 'error', 'message': 'Admin edit_fields(), key={}' + str(e)})
        
        if request.method == 'POST':
            # write the data
            try:
                old_data = self.app.db[coll].find_one(key)
                data = dict(request.forms)
                if '_id' in data:
                    data.pop('_id')
                if 'csrf_token' in data:
                    data.pop('csrf_token')
                self.app.db[coll].update_one(key, {'$set': data})
                data['_id'] = id
            except Exception as e:
                return jsonify({'status': 'error', 'message': 'Admin edit_fields() update_one, ' + str(e)})
            
            return redirect(url_for('admin_view_collection', coll=coll))
        else:
            # view the data
            try:
                data = self.app.db[coll].find_one(key)
                data['_id'] = str(data['_id'])
                fields = fields_transform(data)
            except Exception as e:
                return jsonify({'status': 'error', 'message': 'Admin edit_fields(), find_one(), view ' + str(e)})
            
            return render_template('admin/edit_fields.html', coll=coll, fields=fields, id=data['_id'])

    
    def edit_json(self, coll, id):
        """render a specific record as JSON"""
        if not self.login_check():
            return abort(401)        
        try:
            key = {'_id': ObjectId(id)}
            data = self.app.db[coll].find_one(key)
        except Exception as e:
            return jsonify({'status': 'error', 'message': 'Admin edit_json() key, ' + str(e)})
        
        if request.method == 'POST':
            try:
                raw = dict(request.forms)
                text_format = raw.get('content')
                data = json.loads(text_format)
                #self.app.db[coll].update_one(key, {'$set': data})
                self.app.db[coll].replace_one(key, data)
            except Exception as e:
                return jsonify({'status': 'error', 'message': 'Admin edit_json() replace_one(), ' + str(e)})
            
            return redirect( url_for('admin_view_collection', coll=coll) )
        
        else:
            # render the JSON
            if '_id' in data:
                data.pop('_id')
            return render_template('admin/edit_json.html', coll=coll, content=json.dumps(data), error=None)
        
        
    def edit_schema(self, coll, id):
        """
        edit_schema('collectionName', id) - edit collection item with based on a schema
        
        coll - collection name
        id - the database id
        
        supports GET and POST methods
        """
        if not self.login_check():
            return abort(401)        
        try:
            key = {'_id': ObjectId(id)}
        except Exception as e:
            return jsonify({'status': 'error', 'message': 'Admin edit_schema(), key error, ' + str(e)})
        
        # view the data
        try:
            schema = self.app.db['_meta'].find_one({'name':coll})
            data = self.app.db[coll].find_one(key)
            fields = schema_transform(data, schema)
            data['_id'] = str(data['_id'])
        except Exception as e:
            return jsonify({'status': 'error', 'message': 'Admin edit_schema(), view' + str(e)})
        
        return render_template('admin/edit_schema.html', coll=coll, fields=fields, id=data['_id'])
 
        
    def add_collection_item(self, coll):
        """Add a new item to the collection, raw JSON"""
        if not self.login_check():
            return abort(401)        
        if request.method == 'GET':    
            return render_template('admin/add_json.html', coll=coll)
        else:
            raw = request.forms.get('content')
            try:
                data = json.loads(raw)
            except:
                data = cook_data(raw)
            self.app.db[coll].insert_one(data)
            data['_id'] = str(data['_id'])
        return redirect( url_for('admin_view_collection', coll=coll) )
  
    
    def add_mod_collection(self, coll=None):
        """Add or Modify a collection"""
        if not self.login_check():
            return abort(401)        
        fields = {}
        key = None
        if coll:
            # find record of schema
            fields['name'] = coll
            rec = self.app.db['_meta'].find_one({'name':coll})
            if rec:
                key = {'_id': rec['_id']}
                fields['schema'] = rec['schema']
            
        if request.method == 'POST':
            fields = dict(request.forms)
            name = fields.get('name')
            if name is None:
                return redirect( url_for('admin_view_all') )
            
            schema = fields.get('schema')
            meta = {'name': name, 'schema': schema}
            if schema:
                if key:
                    # since it exists, replace
                    self.app.db['_meta'].replace_one(key, meta)
                else:
                    # it's new insert
                    self.app.db['_meta'].insert_one(meta)
                
            # create the collection if it doesn't exist
            if not name in self.app.db.list_collection_names():
               id = self.app.db[name].insert_one({}).inserted_id
               self.app.db[name].delete_one({'_id':id})
            
            return redirect( url_for('admin_view_all') )
        
        return render_template('admin/add_mod_collection.html', fields=fields)
    
    
    def delete_collection_item(self, coll, id):
        if not self.login_check():
            return abort(401)        
        try:
            key = {'_id': ObjectId(id)}
            old_data = self.app.db[coll].find_one(key)
        except Exception as e:
            return jsonify({'status': 'error', 'message': 'deleteJSON non-existent id, ' + str(e)})
    
        self.app.db[coll].delete_one(key)
        return redirect( url_for('admin_view_collection', coll=coll) )
    
    
    def delete_collection_prompt(self, coll):
        """delete collection with prompt"""
        if not self.login_check():
            return abort(401)        
        fields = {}
        if request.method == 'POST':
            fields = dict(request.forms)
            if fields.get('name') == coll and fields.get('agree') == 'on':
                self.app.db[coll].drop()
            return redirect( url_for('admin_view_all') )
                
        return render_template('admin/delete_collection_prompt.html', fields=fields, coll=coll)
    
    
    def delete_collection(self, coll):
        """DANGER -- this method will delete a collection immediately"""
        if not self.login_check():
            return abort(401)        
        self.app.db[coll].drop()
        return redirect( url_for('admin_view_all') )
   
    
    def unit_tests(self):
        """simple test of connectivity.  more tests should be included in separate module"""
        name = '__test_collection'
        _id = self.app.db[name].insert_one({}).inserted_id
        names = self.app.db.list_collection_names()
        assert(name in names)
        self.app.db[name].drop()
        print("*** All tests passed ***")

    
    def get_users(self):
        """get_users() - return a list of all users JSON records"""
        if _db is None:
            raise ValueError("Database not initialized!")
        return list(_db[self.users_collection].find())
    
    
    def get_user(self, username=None, uid=None):
        """get_user(username, uid) ==> find a user record by uid or username
        : param {username} : - a specific username (string)
        : param {uid} : - a specific user id (string) - note, this is actual '_id' in databse
        : return : a user record or None if not found
        """
        if _db is None:
            raise ValueError("Database not initialized!")
        # first try the username--
        user = None
        if username:
            user = _db[self.users_collection].find_one({'username': username})
        if uid:
            user = _db[self.users_collection].find_one({'_id':uid})
        return user
    
    
    def create_user(self, username, password, **kwargs):
        """
        create_user(username, password, **kwargs) ==> create a user --
        : param {username} and param {password} : REQUIRED
        : param **kwargs : python style (keyword arguments, optional)
        : return : Boolean True if user successfully created, False if exisiting username
        example
        create_user('joe','secret',display_name='Joe Smith',is_editor=True)
        """
        user = self.get_user(username=username)
        if user:
            # user exists, return failure
            return False
        # build a user record from scratch
        user = {'username':username, 'password': encrypt_password(password)}
        for key, value in kwargs.items():
            user[key] = value
    
        _db[self.users_collection].insert_one(user)
        return True
    
    
    def update_user(self, username, **kwargs):
        """
        update_user(username, **kwargs) - update a user record with keyword arguments
        : param {username} : an existing username in the database
        : param **kwargs : Python style keyword arguments.
        : return : True if existing username modified, False if no username exists.
        update a user with keyword arguments
        return True for success, False if fails
        if a keyword argument is EXPLICITLY set to None,
        the argument will be deleted from the record.
        NOTE THAT TinyMongo doesn't implement $unset
        """
        user = self.get_user(username)
        if user:
            idx = {'_id': user['_id']}
            for key, value in kwargs.items():
                if value is None and key in user:
                    # delete the key
                    _db[self.users_collection].update_one(idx, {'$unset': {key:""}} )
                else:
                   # user[key] = value
                   _db[self.users_collection].update_one(idx, {'$set': {key:value}} )
            return True
        return False
    
    
    def delete_user(self, username=None, uid=None):
        """delete_user(username, uid) deletes a user record by username or uid
        : param {username} : string username on None
        : param {uid} : string database id or None
        : return : returns user record upon success, None if fails
        """
        user = None
        if username:
            user = self.get_user(username=username)
        if uid:
            user = self.get_user(uid=uid)
        if user:
            _db[self.users_collection].remove(user)
        return user
    
    
    def authenticate(self, username, password):
        """
        authenticate(username, password) ==> authenticate username, password against datastore
        : param {username} : string username
        : param {password} : string password in plain-text
        : return : Boolean True if match, False if no match
        """
        user = self.get_user(username)
        if user:
            if check_encrypted_password(password, user['password']):
                return True
        return False
    
    
    def render_login(self, login_filename=None):
        """
        render_login(login_filename=None) returns a login page as a string contained
        login_file if None, then if loads module level file login.html
        
        : param {login_filename} : string of filename of login page HTML document or None.
        If None, then the package level standard login.html is loaded.
        : return : string HTML of login page
        NOTE: this is an experimental feature
        """
        # use module level 'login.html''
        if login_filename is None:
            moduledir = os.path.dirname(__file__)
            login_filename = os.path.join(moduledir, 'login.html')
        if not isinstance(login_filename, str):
            raise TypeError("ERROR: minmus_users.login_page() - login_filename must be a string")
        with open(login_filename) as fp:
            data = fp.read()
        return data
    
    
    def user_services_cli(self, args):
        """command line interface for user services"""
        if '--createuser' in args:
            username = input('Username (required): ')
            realname = input('Real Name: ')
            email = input('Email: ')
            password = input('Password (required):')
            self.create_user(username, password, realname=realname, email=email)
            print("Created user")
            return True
            
        if '--deleteuser' in args:
            username = input('Username (required): ')
            self.delete_user(username)
            print("Deleted user")
            return True
            
        if '--listusers' in args:
            users = self.get_users()
            for user in users:
                print(user)
            return True
        
        if '--updateuser' in args:
            username = input('Username (required): ')
            realname = input('Real Name: ')
            email = input('Email: ')
            password = input('Password (required):')
            self.update_user(username, password, realname=realname, email=email)
            print("Updated user")
            return True
        
        if len(args) > 1:
            print('user services:')
            print('  --createuser')
            print('  --deleteuser')
            print('  --listusers')
            print('  --updateuser')
            return True
            
        return False    
    
    
def schema_transform(data, schema):
    """schema_transform(data, schema) - create fields from data document and schema
    :param data - the document data
    :param schema - the document schema
    return fields
    """
    # grab the schema buffer
    schema_lines = schema.get('schema').split('\n')
    fields = []
    for line in schema_lines:
        if line:
            field = {}
            parts = line.split(':') # break it on ':'
            field['name'] = parts[0].strip() # the name part
            subparts = parts[1].strip().split(' ') # split it on spaces
            field['type'] = subparts[0].strip() # get the type
            if len(subparts) > 2:
                field['label'] = ' '.join(subparts[1:])
            else:
                field['label'] = field['name'].title()
            # if value is missing, make it an empty string
            field['value'] = data.get(field['name'], '')
            fields.append(field)
    return fields
    
    
def fields_transform(fields):
    """transform fields to be used in form"""
    nfields = []
    for key, value in fields.items():
        nf = {}
        nf['name'] = key
        nf['value'] = str(value)
        nf['label'] = key.capitalize()
        if '\n' in nf['value']:
            nf['type'] = 'textarea'
        else:
            nf['type'] = 'text'
        nfields.append(nf)
    return nfields


def cook_data(raw_data):
    """cook data to be used in form"""
    data = {}
    lines = raw_data.split('\n')
    for line in lines:
        if ':' in line:
            key, value = line.split(':')
            key = key.strip()
            data[key] = value.strip()
    return data


if __name__ == '__main__':
    print("... Bottle_Simple_Admin is not intended for direct execution. ...")
    print("done")
