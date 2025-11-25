from flask import Flask, request, redirect, flash, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, logout_user, login_user, login_required, current_user
import boto3
import json 
from flask_jwt_extended import JWTManager
from datetime import timedelta

jwt = JWTManager()
db = SQLAlchemy()
bcrypt = Bcrypt()

def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")
    app.config["JWT_SECRET_KEY"] = "at-least-32-characters-long-secret-key"
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]  # Store tokens in cookies
    app.config["JWT_COOKIE_SECURE"] = False  # Set to True in production with HTTPS
    app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # Enable CSRF protection
    app.config["JWT_ACCESS_COOKIE_PATH"] = "/"
    app.config["JWT_REFRESH_COOKIE_PATH"] = "/"
    app.config["JWT_COOKIE_SAMESITE"] = "Lax"  # CSRF protection
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
    db.init_app(app)
    bcrypt.init_app(app)
    jwt.init_app(app)
    from .auth.routes import auth
    app.register_blueprint(auth)
    from .models import users

    with app.app_context():
        db.create_all()



    return app

