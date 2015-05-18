"""loginbp.py"""

import logging
from os.path import dirname

from flask import Blueprint
from flask import render_template, request, flash, redirect, url_for
from flask_login import UserMixin, LoginManager, login_user, logout_user
from flask_wtf import Form
from wtforms import StringField, PasswordField, validators
from flask_assets import Environment, Bundle
from jsonrpcclient import Server
from jsonrpcclient.exceptions import ReceivedErrorResponse


logger = logging.getLogger(__name__)
loginbp = Blueprint('loginbp', __name__, template_folder='templates',
    static_folder='static')
login_manager = LoginManager()
users_api = Server('http://localhost/api/users', auth=('admin', 'heiwah4i'))


@loginbp.record_once
def on_load(state):
    # webassets
    assets = state.app.assets
    assets.append_path(dirname(__file__)+'/static')
    js_login = Bundle('js/jQuery-Notify-bar/jquery.notifyBar.js', 'js/login.js',
        filters='jsmin', output='packed-login.js')
    assets.register('js_login', js_login)
    css_login = Bundle('js/jQuery-Notify-bar/css/jquery.notifyBar.css',
        'css/login.css', filters='cssmin', output='packed-login.css')
    assets.register('css_login', css_login)
    # loginbp
    login_manager.init_app(state.app)


class User(UserMixin):
    def __init__(self, user_id, username):
        self.user_id = user_id
        self.username = username

    def get_id(self):
        return self.user_id


@login_manager.user_loader
def load_user(user_id):
    """Load user"""
    user_dict = users_api.get_id(user_id, response=True)
    user = User(user_id, user_dict['username'])
    return user


class LoginForm(Form):
    """Login form"""
    username = StringField('Username', validators=[validators.required()])
    password = PasswordField('Password', validators=[validators.required()])


@loginbp.route('/login', methods=['GET', 'POST'])
def login():
    """Login"""
    form = LoginForm()
    if form.validate_on_submit():
        username = request.form['username']
        password = request.form['password']
        try:
            user_dict = users_api.login(username=username, password=password,
                response=True)
        except ReceivedErrorResponse as e:
            flash('Invalid username or password')
        except Exception as e:
            logger.error(str(e))
            flash('Sorry, but you could not log in')
        else:
            user = User(user_dict['id'], username)
            if login_user(user, remember=True):
                flash('Logged in as %s' % username)
                return redirect(request.args.get('next') or url_for('promos'))
            else:
                flash('Sorry, but you could not log in')
    return render_template('login.html', url=url_for('.login'), form=form)


@loginbp.route('/logout')
def logout():
    """Logout"""
    logout_user()
    flash('Logged out.')
    return redirect(url_for('.login'))
