import os
import secrets

class Config:
    SECRET_KEY = secrets.token_hex(32)

    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:Ethosfans!24@localhost/login_information"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


    Debug = True