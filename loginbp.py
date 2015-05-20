"""loginbp.py"""

import logging
from os.path import dirname

from flask import render_template, request, flash, redirect, url_for, \
    Blueprint, current_app, session
from flask_assets import Bundle
from wtforms import StringField, PasswordField, validators
from flask_wtf import Form
from flask_login import UserMixin, LoginManager, login_user, logout_user, \
    login_required, current_user
from flask_principal import Principal, Identity, AnonymousIdentity, UserNeed, \
    RoleNeed, identity_loaded, identity_changed
from jsonrpcclient import Server
from jsonrpcclient.exceptions import ReceivedErrorResponse


# Logging
logger = logging.getLogger(__name__)
# Instantiate the blueprint
loginbp = Blueprint('loginbp', __name__, template_folder='templates', \
    static_folder='static')
# Flask-Login
login_manager = LoginManager()
# Users API for retrieving user data
users_api = Server('http://localhost/api/users', auth=('admin', 'heiwah4i'))


@loginbp.record_once
def on_load(state):
    """Perform blueprint actions that require the app variable"""
    # Flask-Login
    login_manager.init_app(state.app)
    # Flask-Principal
    Principal(state.app, skip_static=True)
    @identity_loaded.connect_via(state.app)
    def on_identity_loaded(_, identity): #pylint:disable=unused-variable
        """Flask-Principal: Called when logging in or out"""
        identity.user = current_user
        # UserNeeds
        if hasattr(current_user, 'username'):
            logger.info('Identity loaded: %s', current_user.username)
            identity.provides.add(UserNeed(current_user.username))
        # RoleNeeds
        if hasattr(current_user, 'roles'):
            for role in current_user.roles:
                identity.provides.add(RoleNeed(role.name))
    # Webassets
    assets = state.app.assets
    assets.append_path(dirname(__file__)+'/static')
    js_login = Bundle('js/jQuery-Notify-bar/jquery.notifyBar.js', \
        'js/login.js', filters='jsmin', output='packed-login.js')
    assets.register('js_login', js_login)
    css_login = Bundle('js/jQuery-Notify-bar/css/jquery.notifyBar.css', \
        'css/login.css', filters='cssmin', output='packed-login.css')
    assets.register('css_login', css_login)


class User(UserMixin):
    """Instantiated when login was successful, populated with data returned
    from the api, then passed to Flask-Login methods.
    """
    def __init__(self, user_id, username):
        self.user_id = user_id
        self.username = username

    def get_id(self):
        return self.user_id


@login_manager.user_loader
def load_user(user_id):
    """Flask-Login: Load user"""
    user_dict = users_api.get_id(user_id, response=True)
    user = User(user_id, user_dict['username'])
    return user


@loginbp.route('/login', methods=['GET', 'POST'])
def login():
    """Login route"""
    class LoginForm(Form):
        """Login form"""
        username = StringField('Username', validators=[validators.required()])
        password = PasswordField('Password', validators=[validators.required()])
    form = LoginForm()
    # Validate form
    if form.validate_on_submit():
        username = request.form['username']
        password = request.form['password']
        # Attempt login via api
        try:
            user_dict = users_api.login(username=username, password=password, \
                response=True)
        except ReceivedErrorResponse as e:
            logger.warning('Invalid username or password')
            flash('Invalid username or password')
        except Exception as e:
            logger.error(str(e))
            flash('Sorry, but you could not log in')
        else:
            user = User(user_dict['id'], username)
            if login_user(user, remember=True):
                # Flask-Principal
                identity_changed.send(current_app._get_current_object(), \
                    identity=Identity(user.user_id))
                # Redirect
                logger.info('Logged in as %s', username)
                flash('Logged in as %s' % username)
                return redirect(request.args.get('next') or url_for('home'))
            else:
                logger.error('Sorry but you could not log in')
                flash('Sorry, but you could not log in')
    return render_template('login.html', url=url_for('.login'), form=form)


@loginbp.route('/logout')
@login_required
def logout():
    """Logout route"""
    # Flask-Login
    logout_user()
    # Flask-Principal: Remove session keys
    for key in ('identity.name', 'identity.auth_type'):
        session.pop(key, None)
    # Flask-Principal: Set identity to anonymous
    identity_changed.send(current_app._get_current_object(), \
        identity=AnonymousIdentity())
    # Redirect
    logger.info('Logged out')
    flash('Logged out.')
    return redirect(url_for('.login'))
