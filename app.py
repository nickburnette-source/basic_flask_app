from flask import Flask, render_template, redirect, url_for, request, abort, send_from_directory
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from logging.handlers import RotatingFileHandler
import json
import base64
import os
import sys


# gunicorn -w 2 -b :7002 --chdir /opt/webapp app:app
BASE_PATH = 'data/'
LOG_PATH = '/var/log/flask/app.log'
LOG_PATH = 'C:\\Users\\nickb\\Documents\\repo\\basic_flask_app\\app.log'

LOG_LEVEL = logging.DEBUG

# Before running, be sure to create a database.db in the working directory.
# python
# >>> conn = sqlite3.connect('database.db')
# >>> conn.commit()
# >>> conn.close()
#
# Then run python again:
# >>> from app import db
# >>> db.create_all()


app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret key'
# raise KeyError('You first need to generate a secret key!')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_PATH, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

handler = RotatingFileHandler(LOG_PATH, maxBytes=1000000, backupCount=5)
handler.setLevel(LOG_LEVEL)

formatter = logging.Formatter('%(asctime)s - %(pathname)s: line %(lineno)d - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

logger = logging.getLogger('werkzeug')
logger.addHandler(handler)
logger.setLevel(LOG_LEVEL)

logger.info('Program Start')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    permission = db.Column(db.Integer)
    # Permission Tier List
    #   0 - Admin
    #   1 - Level 1
    #   2 - Level 2
    #   3 - Level 3


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


# *********************************************************************************************************************
# ******************************************        Basic Endpoints        ********************************************
# *********************************************************************************************************************


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')


@app.route('/static/<path:path>')
def static_file(path):
    return send_from_directory(os.path.join(sys.path[0], 'static'), path)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return render_template('login.html', form=form, success=False)

    return render_template('login.html', form=form, success=True)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        # if form.email.data.endswith('@domain.com'):  Add this for security to filter out a specific domain name
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, permission=5)
        db.session.add(new_user)
        db.session.commit()
        return render_template('signup.html', form=form, success=True)
        return render_template('signup.html', form=form, success=False)
    return render_template('signup.html', form=form, success=None)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username, permission=current_user.permission)


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', name=current_user.username, permission=current_user.permission,
                           email=current_user.email)


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', username=current_user.username, email=current_user.email)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# *********************************************************************************************************************
# *****************************************        Advanced Endpoints        ******************************************
# *********************************************************************************************************************


@app.route('/ui/update')
@login_required
def update_audit():
    return


@app.route('/ui/users', methods=['POST', 'GET'])
@login_required
def edit_users():
    if request.method == 'GET':
        user_list = []
        for user in User.query.all():
            if not user.username == current_user.username:
                if user.permission >= current_user.permission:
                    user_list.append([user.username, user.permission])
        return json.dumps(user_list, sort_keys=True)
    if request.method == 'POST':
        if int(request.args['level']) >= current_user.permission:
            User.query.filter_by(username=request.args['user']).first().permission = int(request.args['level'])
            db.session.commit()
            return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}
        else:
            abort(403)


@app.route('/ui/profile', methods=['POST',])
@login_required
def edit_profile():
    if 'username' in request.args:
        current_user.username = request.args['username']
        db.session.commit()
        return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}
    if 'email' in request.args:
        current_user.email = request.args['email']
        db.session.commit()
        return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}
    if 'krabbypattyrecipe' in request.args:
        current_user.password = generate_password_hash(
            base64.b64decode(request.args['krabbypattyrecipe']).decode('utf-8'), method='sha256')
        db.session.commit()
        return json.dumps({'success': True}), 200, {'ContentType': 'application/json'}


# User.query.get(1).password = generate_password_hash('password', method='sha256')
# db.session.commit()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True, threaded=False)

