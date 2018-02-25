from app import app, db
from app.models import User
from flask import redirect, url_for, flash, render_template, request, abort
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
import pandas as pd
import os
import jwt


def admin_required(f):
    """Decorator to prevent non-administrators from accessing admin content."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            return abort(401)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title='Home')


@app.route('/admin_login', methods=['GET', 'POST'])
def login():
    # if user tries to go to this page when they're already logged in
    if current_user.is_authenticated:  # attr from flask_login UserMixin
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():  # activated when submitted
        # use SQLAlchemy query to get record for the user trying to login
        user = User.query.filter_by(username=form.username.data).first()
        # next line checks if user wasn't in db or if the password didn't match
        if user is None or not user.check_password(form.password.data):
            flash('invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        # next, handle redirect to original page if sent by @login_required
        next_page = request.args.get('next')
        # if the user went straight to login (there wasn't a redirect to login)
        # OR! if there was a full URL in the next argument (for security to
        # prevent malicious redirects)
        if not next_page or url_parse(next_page).netloc != '':
            # set it up to redirect to index
            next_page = url_for('index')
        return redirect(next_page)
    # render the login page if the form wasn't submitted already
    return render_template('login.html', title='Sign In', form=form)
