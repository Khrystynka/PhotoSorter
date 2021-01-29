from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from google.cloud import storage
gcs = storage.Client()
CLOUD_STORAGE_BUCKET='uploads_photos'
bucket = gcs.get_bucket(CLOUD_STORAGE_BUCKET)



app = Flask(__name__)

# UPLOAD_FOLDER = os.path.join(os.getcwd(), '‎⁨UploadedFiles')
UPLOAD_FOLDER = "/Users/khrystyna/Desktop/PhotoProject/Server/server/UploadedFiles"
GOOGLE_KEY_PATH= "/Users/khrystyna/Desktop/PhotoProject/Server/server/googlecloudkey.json"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'Imverysecretkey'
app.config['GOOGLE_APPLICATION_CREDENTIALS']= GOOGLE_KEY_PATH
API_KEY='AIzaSyDAt8g4YfuPX9-jBhCMmo9x0rYJaiv98TE'
# app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///uploads.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

from server import routes