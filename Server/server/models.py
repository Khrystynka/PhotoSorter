from server import db
from datetime import datetime


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), nullable=False,default='test@gmail.com')
    password = db.Column(db.String(120), nullable=False)
    avatar = db.Column(db.String(20), nullable=False, default='default.jpg')
    upload = db.relationship('Upload', backref='author', lazy=True)

    def __repr__(self):
        return f"User ({self.username},{self.email},{self.password},{self.upload})"


class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(120), unique=False, nullable=False)
    path = db.Column(db.String, unique=True, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'),
                        nullable=True)

    def __repr__(self):
        return f"File ({self.original_name},{self.path},{self.date},{self.user_id})"
