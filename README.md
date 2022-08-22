# bottle_simple_admin

The purpose of this repository is to provide a simple adminstration and user authentication for Bottle.

## requirements

* bottle (https://github.com/bottlepy/bottle)
* bottle_session (https://github.com/jefmud/bottle_session)

# Installation

```
$ mkdir sample-proj
$ cd sample-proj
$ git clone https://github.com/jefmud/bottle_session
$ git clone https://github.com/jefmud/bottle_simple_admin
```

# Usage

Here's a simple program that uses `bottle_simple_admin`

```
from bottle import Bottle, TEMPLATE_PATH, jinja2_template
from bottle_session import Session
from bottle_simple_admin import Admin, url_for, render_template
import sys

# Initialize Bottle, session, and admin
app = Bottle()
session = Session('somethingsSecret')
admin = Admin(app, session)

# THIS IS OF KEY IMPORTANCE!!
TEMPLATE_PATH[:] = ['templates', 'bottle_simple_admin/templates']

@app.route('/')
def index():
    return """
    <html>
    <body>Admin interface - <a href="/admin">click here</a></body>
    </html>
    """

if __name__ == '__main__':
    if '--runserver' in sys.argv:
        app.run(port=5000, server="paste")
    else:
        admin.user_services_cli(sys.argv)
    print('requires command after script e.g. --runserver, --createuser, etc.')
```

# getting ready

We will have to create a user or two before running the program.

```
$ python app.py --createuser
Username (required): admin
Real Name: Admin User
Email: admin@example.com
Password (required):password
Created user
```

# Running our program

```
$ python app.py --runserver
Bottle v0.12.23 server starting up (using PasteServer())...
Listening on http://127.0.0.1:5000/
Hit Ctrl-C to quit.

serving on http://127.0.0.1:5000
```

# Finally
Have fun!

