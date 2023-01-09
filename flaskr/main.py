#Program by Quinn Trafas

from flask import Flask, render_template, make_response, request, jsonify, session, redirect, url_for
from flask_restful import Api, Resource, abort, reqparse
import jwt
from datetime import datetime, timezone, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, get_jwt_identity, get_jwt, jwt_required, JWTManager, set_access_cookies, unset_jwt_cookies, verify_jwt_in_request

app = Flask(__name__)
app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=True)
app.secret_key = "should should be super secret ;)"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False #Should be set to true
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=10)
api = Api(app)
jwt = JWTManager(app)

accounts = {"admin": "password", "qq":"sha256$lfOOV1JDqaKiUw92$54f6afdb9bc11fca7f4c647b7a84db0d2207b6ceb1d436525661460ba7cbf258"}
token_blacklist = []

#Custom HTML page for 404 error
@app.errorhandler(404)
def page_not_found(e):
    #Should probably log this activity... :)
    return make_response(render_template('ErrorTemp.html', errorCode="404"), 401)

@jwt.unauthorized_loader
def custom_unauthorized_response(_err):
    resp = make_response(redirect(url_for('login')))
    session.clear()
    unset_jwt_cookies(resp)
    return resp

@jwt.expired_token_loader
def custom_expired_response(jwt_header, jwt_payload):
    resp = make_response(redirect(url_for('login')))
    session.clear()
    unset_jwt_cookies(resp)
    return resp

@jwt.token_in_blocklist_loader
def check_if_revoked(jwt_header, jwt_payload: dict):
    try:
        if get_jwt()["jti"] in token_blacklist:
            return True
        set_access_cookies
        return False
    except:
        return False

#Home page
class Home(Resource):
    @jwt_required(optional=True)
    def get(self):
        print(accounts)
        headers = {'Content-Type': 'text/html'}
        current_user = get_jwt_identity()
        if current_user:
            return make_response(render_template('Index.html', username=current_user, coolVar="What a cool variable!"),200, headers)
        return make_response(render_template('Index.html', coolVar="What a cool variable!"),200, headers)

class Tos(Resource):
    @jwt_required(optional=True)
    def get(self):
        print(accounts)
        headers = {'Content-Type': 'text/html'}
        current_user = get_jwt_identity()
        if current_user:
            return make_response(render_template('Tos.html', username=current_user),200, headers)
        return make_response(render_template('Tos.html'),200, headers)

class Private(Resource):
    @jwt_required()
    def get(self):
        token = get_jwt()
        print(token_blacklist)
        print(token)
        current_user = get_jwt_identity()
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template("Private.html", username=current_user), 200, headers)

class Login(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('LogIn.html'),200, headers)
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("uname", location="form")
        parser.add_argument("psw", location="form")
        args = parser.parse_args()

        #Check if the user exists and if the passwords match
        if args["uname"] in accounts and check_password_hash(accounts[str(args["uname"])], str(args["psw"])):
            #Generate a security token
            other = {"ip":request.remote_addr}
            access_token = create_access_token(identity=args["uname"], additional_claims=other)
            #Set the session username to the login username
            resp = make_response(redirect(url_for("home")))
            set_access_cookies(resp, access_token)
            return resp
        else:
            #If incorrect credentials

            #Should use make_response with a call to login template, providing a failed log in code and the attempted password
            return make_response(render_template("ErrorTemp.html", errorCode="401"), 401)

class SignUp(Resource):
    def get(self):
        headers = {'Content-Type': 'text/html'}
        return make_response(render_template('Signup.html'),200, headers)
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("uname", location="form")
        parser.add_argument("psw", location="form")
        args = parser.parse_args()
        #Check if username already exists
        if not args["uname"] in accounts:
            #If username doesn't exist
            hashed_psw = generate_password_hash(args["psw"], method="sha256")
            accounts[args["uname"]] = hashed_psw
            headers = {'Content-Type': 'text/html'}
            return make_response(redirect(url_for("login")))
        else:
            #If username exists
            return make_response(render_template("ErrorTemp.html", errorCode="401"), 401)

class LogOut(Resource):
    @jwt_required()
    def get(self):
        jti = get_jwt()["jti"]
        token_blacklist.append(jti)
        session.clear()
        resp = make_response(redirect(url_for("home")))
        unset_jwt_cookies(resp)
        return resp

api.add_resource(Home, "/", "/home") #Multiple URLs assigned to the same resource
api.add_resource(Private, "/private")
api.add_resource(Login, "/login")
api.add_resource(SignUp, "/signup")
api.add_resource(LogOut, "/logout")
api.add_resource(Tos, "/tos")

if __name__ == '__main__':
    app.run(debug=True)