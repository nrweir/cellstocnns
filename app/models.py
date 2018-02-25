from app import app, db, login
from datetime import datetime
from time import time
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from hashlib import md5


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    oligos = db.relationship('Oligos', backref='Creator', lazy='dynamic')
    about_me = db.Column(db.String(140))  # TRM
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    validated = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    title = db.Column(db.String(100), nullable=False)
    short_title = db.Column(db.String(20), nullable=False)
    slug = db.Column(db.String(100), nullable=False, unique=True)
    published_date = db.Column(db.Date, nullable=False)
    updated_date = db.Column(db.Date)
    body = db.Column(db.String(35000))
    author = db.Column(db.Integer, db.ForeignKey('user.id'))


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    author = db.Column(db.String(50), nullable=False)
    published_date = db.Column(db.Date, nullable=False)
    body = db.Column(db.String(1000))
    target_post = db.Column(db.Integer, db.ForeignKey('post.id'))
