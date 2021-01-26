from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# UPLOAD_FOLDER = os.path.join(os.getcwd(), '‎⁨UploadedFiles')
UPLOAD_FOLDER = "/Users/khrystyna/Desktop/PhotoProject/Server/server/UploadedFiles"

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'Imverysecretkey'

# app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///uploads.db'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
from server import routes