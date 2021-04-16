import os
from dotenv import load_dotenv
from datetime import datetime
from datetime import timedelta


load_dotenv()

class BaseConfig(object):
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
    UPLOAD_FOLDER=os.getenv('UPLOAD_FOLDER')
    SECRET_KEY = os.getenv('SECRET_KEY')
    API_KEY=os.getenv('API_KEY')
    JWT_SECRET_KEY = os.getenv('SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES=timedelta(minutes=20)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    SQLALCHEMY_TRACK_MODIFICATIONS = False


