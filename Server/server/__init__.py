from flask import Flask
from flask_sqlalchemy import SQLAlchemy 
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
import os
from dotenv import load_dotenv
load_dotenv()
from google.cloud import storage
# from flask import jsonify
# from flask import request

from flask_jwt_extended import JWTManager
gcs = storage.Client()
bucket = gcs.get_bucket(os.getenv('CLOUD_STORAGE_BUCKET'))
jwt = JWTManager()
db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()

def create_app(config_object):
    app = Flask(__name__)
    app.config.from_object(config_object)
    
    jwt.init_app(app)
    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    
    if not app.testing:
        print('Real app not testing')
    else:
        print('Testing is going on here')
    from server import routes
    app.register_blueprint(routes.bp)
    print(app.testing)
    return app

