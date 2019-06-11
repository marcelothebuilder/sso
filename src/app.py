import json

import flask
from flask import Flask, render_template, g
import flask_login
from flask_login import login_required
from flask_oidc import OpenIDConnect

from model.user import User

app = Flask(__name__)

login_manager = flask_login.LoginManager()
login_manager.init_app(app)

app.config.update({
    'SECRET_KEY': 'pikachu',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_SCOPES': [
        "openid",
        "address",
        "email",
        "microprofile-jwt",
        "offline_access",
        "phone",
        "profile",
        "roles",
        "web-origins"
    ],
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False, # MUST be True in production
    'OIDC_REQUIRE_VERIFIED_EMAIL': False, # SHOULD be True in production
    'OIDC_VALID_ISSUERS': ['http://localhost:8080/auth/realms/flask-test'],
    'OIDC_OPENID_REALM': 'http://localhost:5000/oidc_callback',
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})
oidc = OpenIDConnect(app)

@app.route('/')
def hello_world():
    if oidc.user_loggedin:
        return ('Hello, %s, <a href="/private">See private</a> '
                '<a href="/logout">Log out</a>') % \
            oidc.user_getfield('email')
    else:
        return 'Welcome anonymous, <a href="/private">Log in</a>'


@app.route('/private')
@oidc.require_login
def hello_me():
    info = oidc.user_getinfo(["aud", # user realm
        "sub", # the user id
        "auth_time",
        "name", # full name
        "given_name", # first name
        "family_name", # last name
        "preferred_username", #username
        "email" # email
        ])
    print(info)
    return ('Hello, %s (%s)! <a href="/">Return</a>' %
            (info.get('email'), info.get('sub')))


@app.route('/api')
@oidc.accept_token(True, ['openid'])
def hello_api():
    return json.dumps({'hello': 'Welcome %s' % g.oidc_token_info['sub']})


@app.route('/logout')
def logout():
    oidc.logout()
    return 'Hi, you have been logged out! <a href="/">Return</a>'


if __name__ == '__main__':
    app.run('localhost', port=5000)
