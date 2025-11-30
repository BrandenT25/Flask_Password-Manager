from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, make_response
from .. import db
from ..models import users
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token, set_access_cookies, set_refresh_cookies, unset_jwt_cookies
from .. import jwt

auth = Blueprint('auth', __name__)
bcrypt = Bcrypt()





@auth.route('/home')
def home():
    return render_template('home.html')


@auth.route('/dashboard')
@jwt_required()
def dashboard():
    userid =  get_jwt_identity()
    user = users.query.filter_by(id=userid).first()
    return render_template('dashboard.html', username=user.username)


@auth.route('/register')
def register():
    return render_template('register.html')


@auth.route('/login')
def login():
    return render_template('login.html')



@auth.route('/api/auth/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    if not confirm_password or not password or not username:
        return jsonify({"error": "please make sure all fields are filled out"}), 400
    if confirm_password != password:
        return jsonify({"error": "password and confirm password dont match"}), 400
    existing_user = users.query.filter_by(username=username.lower()).first()
    if existing_user:
        return jsonify({"error": "this username is already taken please choose a different one"}), 400
    
    new_user = users(username=username)
    new_user.set_password(password)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"Sucess": "User sucessfully Registered"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"Error": "There was an error with registering try again"}), 400
        


@auth.route('/api/auth/login' , methods=['POST'] )
def api_login():
    data = request.get_json()
    username = data.get('username').lower()
    password = data.get('password')
    if not password or not username:
        return jsonify({"error":"Please make sure all fields are filled out"}), 400 
    user = users.query.filter_by(username=username).first()
    if not user or not user.check_password(password=password):
        return jsonify({"error": "invalid credentials"}), 401
    access_token = create_access_token(identity=str(user.id))
    refresh_token = create_refresh_token(identity=str(user.id))
    response = make_response(jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token
    }), 200)

    set_access_cookies(response, access_token)
    set_refresh_cookies(response, refresh_token)
    return response

#@auth.route('/api/auth/fetch-user-info', methods=['POST'])
#def api_fetch_user():
    #data = request.get_json()



@auth.route('/logout')
def logout():
    logout_user()
    flash("logged out sucessfully")
    return redirect(url_for('login'))
