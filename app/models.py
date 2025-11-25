from . import db
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()

class users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(80), unique  = True, nullable = False)
    password  = db.Column(db.String(120), unique = False, nullable = False)

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        
        return bcrypt.check_password_hash(self.password, password)

