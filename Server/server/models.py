from server import db, login_manager
from datetime import datetime
from flask_login import UserMixin
from server import bcrypt




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model,UserMixin):
# class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False,default='test@gmail.com')
    password = db.Column(db.String(120), nullable=False)
    uploads= db.relationship('Upload', backref='author', lazy=True)

    def hash(password):
        return bcrypt.generate_password_hash(password).decode('utf-8')
    def __repr__(self):
        return f"User ({self.username},{self.email},{self.password},{self.uploads})"

tags= db.Table('tags',
    db.Column('tag', db.String(120), db.ForeignKey('tag.name')),
    db.Column('upload_id', db.Integer, db.ForeignKey('upload.id')))

class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(120), unique=False, nullable=False)
    hash_name = db.Column(db.String(120), unique=True, nullable=False)
    cloud_path = db.Column(db.String, unique=True, nullable=False)
    date_uploaded = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),nullable=True)
    tags = db.relationship('Tag', secondary=tags)

    def __repr__(self):
        return f"Upload ({self.original_name},{self.cloud_path},{self.date_uploaded},{self.user_id},{self.tags})"

class Tag(db.Model):
    name = db.Column(db.String(120), nullable=False,unique=True,primary_key=True)
    # uploads = db.relationship('Upload', secondary = tags, lazy=True)

    def __repr__(self):
        return f"Tag ({self.name})"



