import os
import secrets
from app.aws_secrets import get_aws_secret

class Config:

    SECRETS = get_aws_secret("dev/flask")


    SECRET_KEY = SECRETS["SECRET_KEY"]

    SQLALCHEMY_DATABASE_URI = f"postgresql://{SECRETS["DB_USER"]}:{SECRETS["DB_PASS"]}@{SECRETS["DB_IP"]}:{SECRETS["DB_PORT"]}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False


    Debug = True
