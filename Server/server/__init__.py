from flask import Flask
from flask_sqlalchemy import SQLAlchemy 
from datetime import datetime
from datetime import timedelta
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
import os
from dotenv import load_dotenv
load_dotenv()
from google.cloud import storage
from flask import jsonify
from flask import request

from flask_jwt_extended import JWTManager
from datetime import datetime

gcs = storage.Client()
bucket = gcs.get_bucket(os.getenv('CLOUD_STORAGE_BUCKET'))

app = Flask(__name__)
# app.config.update(
#     SESSION_COOKIE_SECURE=True,
#     SESSION_COOKIE_HTTPONLY=True,
#     SESSION_COOKIE_SAMESITE='None',
# )

app.config['UPLOAD_FOLDER'] =os.getenv('UPLOAD_FOLDER')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['API_KEY']=os.getenv('API_KEY')
# app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config["JWT_SECRET_KEY"] = os.getenv('SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"]=timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)




jwt = JWTManager(app)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

from server import routes