from flask import Blueprint, render_template, redirect, url_for, flash, request
from .. import db
from ..models import users
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt

auth = Blueprint('auth', __name__)
bcrypt = Bcrypt()
def log_user_in(user):
    login_user(user)
    flash(f"Welcome to the dashboard {user.username}")
    return redirect(url_for("auth.dashboard"))


@auth.route('/home')
def home():
    return render_template('home.html')

@auth.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if not password or not username:
            flash("Please input both a username and password")
            return render_template('register.html')
        if password != confirm_password:
            flash("Please make sure your password matches the confirm password")
            return render_template('register.html')


        existing_user = users.query.filter_by(username=username).first()
        if existing_user:
            flash("username already exists")
            return render_template('register.html')

    
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = users(username=username, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash("registration completed")
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash("error with registration try again")
            return render_template("register.html")


    return render_template('register.html')


@auth.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not password or not username:
            flash("Please to make sure to enter a username and password")
            return render_template('login.html')
        
        user = users.query.filter_by(username=username).first()
        if user:
            if bcrypt.check_password_hash(user.password, password):
                return log_user_in(user)
            else:
                flash('wrong password try again')
                return render_template('login.html')
        else:
            flash('enter a valid username')
            return render_template('login.html')
    return render_template('login.html')



@auth.route('/logout')
def logout():
    logout_user()
    flash("logged out sucessfully")
    return redirect(url_for('login'))
