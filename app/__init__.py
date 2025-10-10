from flask import Flask, request, redirect, flash, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, logout_user, login_user, login_required, current_user


db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()


@login_manager.user_loader
def load_user(user_id):
    from .models import users
    return users.query.get(int(user_id))


def create_app():
    app = Flask(__name__)
    app.config.from_object("config.Config")

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    from .auth.routes import auth
    app.register_blueprint(auth)

    return app