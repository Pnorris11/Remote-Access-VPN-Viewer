import os
import logging
from flask import Blueprint, redirect, url_for, session, request, flash, current_app
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from authlib.integrations.flask_client import OAuth
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from functools import wraps

logger = logging.getLogger(__name__)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, email, name=None, groups=None):
        self.id = user_id
        self.email = email
        self.name = name or email
        self.username = email  # Add username property for compatibility
        self.groups = groups or []

    def is_authorized(self):
        """Check if user is authorized based on domain or groups"""
        # Check authorized domains
        authorized_domains = os.getenv('AUTHORIZED_DOMAINS', '').split(',')
        if authorized_domains and authorized_domains[0]:  # If domains are configured
            user_domain = self.email.split('@')[-1] if '@' in self.email else ''
            if user_domain not in [d.strip() for d in authorized_domains]:
                return False
        
        # Check authorized groups
        authorized_groups = os.getenv('AUTHORIZED_GROUPS', '').split(',')
        if authorized_groups and authorized_groups[0]:  # If groups are configured
            if not any(group.strip() in self.groups for group in authorized_groups):
                return False
        
        return True

# Authentication blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

def init_auth(app):
    """Initialize authentication for the Flask app"""
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        # Retrieve user from session
        if 'user_data' in session and session.get('user_id') == user_id:
            user_data = session['user_data']
            return User(
                user_id=user_data['id'],
                email=user_data['email'],
                name=user_data.get('name'),
                groups=user_data.get('groups', [])
            )
        return None
    
    # Initialize OAuth for OIDC
    oauth = OAuth(app)
    
    # Configure OIDC client
    if os.getenv('OIDC_ENABLED', 'False').lower() == 'true':
        try:
            discovery_url = os.getenv('OIDC_DISCOVERY_URL')
            logger.info(f"Initializing OIDC with discovery URL: {discovery_url}")
            
            oidc_client = oauth.register(
                name='oidc',
                client_id=os.getenv('OIDC_CLIENT_ID'),
                client_secret=os.getenv('OIDC_CLIENT_SECRET'),
                server_metadata_url=discovery_url,
                client_kwargs={
                    'scope': 'openid email profile'
                }
            )
            app.oidc_client = oidc_client
            logger.info("OIDC client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize OIDC client: {e}")
            # Don't fail startup, just log the error
    
    app.register_blueprint(auth_bp)

def require_auth(f):
    """Decorator to require authentication and authorization"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if authentication is disabled for debugging
        if os.getenv('DEBUG_DISABLE_AUTH', 'False').lower() == 'true':
            # Create a debug user if not already authenticated
            if not current_user.is_authenticated:
                debug_user = User(
                    user_id='debug-user',
                    email='debug@localhost',
                    name='Debug User',
                    groups=['debug']
                )
                login_user(debug_user)
                session['user_data'] = {
                    'id': 'debug-user',
                    'email': 'debug@localhost',
                    'name': 'Debug User',
                    'groups': ['debug']
                }
                session['user_id'] = 'debug-user'
                logger.info("Debug mode: Auto-logged in as debug user")
            return f(*args, **kwargs)
        
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        
        if not current_user.is_authorized():
            flash('Access denied. You are not authorized to view this resource.', 'error')
            return redirect(url_for('auth.unauthorized'))
        
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/login')
def login():
    """Login route - redirects to appropriate auth method"""
    # Check if authentication is disabled for debugging
    if os.getenv('DEBUG_DISABLE_AUTH', 'False').lower() == 'true':
        debug_user = User(
            user_id='debug-user',
            email='debug@localhost',
            name='Debug User',
            groups=['debug']
        )
        login_user(debug_user)
        session['user_data'] = {
            'id': 'debug-user',
            'email': 'debug@localhost',
            'name': 'Debug User',
            'groups': ['debug']
        }
        session['user_id'] = 'debug-user'
        logger.info("Debug mode: Authenticated as debug user")
        flash('Debug mode: Logged in as Debug User', 'info')
        return redirect(url_for('index'))
    
    oidc_enabled = os.getenv('OIDC_ENABLED', 'False').lower() == 'true'
    saml_enabled = os.getenv('SAML_ENABLED', 'False').lower() == 'true'
    
    if oidc_enabled:
        return redirect(url_for('auth.oidc_login'))
    elif saml_enabled:
        return redirect(url_for('auth.saml_login'))
    else:
        flash('No authentication method configured', 'error')
        return 'Authentication not configured', 500

@auth_bp.route('/oidc/login')
def oidc_login():
    """OIDC login"""
    if not hasattr(current_app, 'oidc_client'):
        flash('OIDC not configured', 'error')
        return redirect(url_for('auth.login'))
    
    redirect_uri = os.getenv('OIDC_REDIRECT_URI') or url_for('auth.oidc_callback', _external=True)
    return current_app.oidc_client.authorize_redirect(redirect_uri)

@auth_bp.route('/oidc/callback')
def oidc_callback():
    """OIDC callback"""
    if not hasattr(current_app, 'oidc_client'):
        flash('OIDC not configured', 'error')
        return redirect(url_for('auth.login'))
    
    try:
        token = current_app.oidc_client.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            user_info = current_app.oidc_client.parse_id_token(token)
        
        # Extract user information
        user_id = user_info.get('sub') or user_info.get('email')
        email = user_info.get('email')
        name = user_info.get('name') or user_info.get('preferred_username')
        groups = user_info.get('groups', [])
        
        # Create user object
        user = User(user_id=user_id, email=email, name=name, groups=groups)
        
        # Check authorization
        if not user.is_authorized():
            flash('Access denied. You are not authorized to access this application.', 'error')
            return redirect(url_for('auth.unauthorized'))
        
        # Store user data in session
        session['user_data'] = {
            'id': user_id,
            'email': email,
            'name': name,
            'groups': groups
        }
        session['user_id'] = user_id
        
        # Log in user
        login_user(user)
        
        logger.info(f"User {email} logged in successfully via OIDC")
        flash(f'Welcome, {name or email}!', 'success')
        
        # Redirect to next page or home (validate redirect URL for security)
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"OIDC callback error: {e}")
        flash('Authentication failed. Please try again.', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/saml/login')
def saml_login():
    """SAML login"""
    try:
        saml_auth = init_saml_auth(init_saml_req(request))
        return redirect(saml_auth.login())
    except Exception as e:
        logger.error(f"SAML login error: {e}")
        flash('SAML authentication failed', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/saml/acs', methods=['POST'])
def saml_acs():
    """SAML Assertion Consumer Service"""
    try:
        saml_auth = init_saml_auth(init_saml_req(request))
        saml_auth.process_response()
        
        errors = saml_auth.get_errors()
        if not errors:
            # Get user attributes
            attributes = saml_auth.get_attributes()
            user_id = saml_auth.get_nameid()
            
            email = attributes.get('email', [user_id])[0] if attributes.get('email') else user_id
            name = attributes.get('name', [email])[0] if attributes.get('name') else email
            groups = attributes.get('groups', [])
            
            # Create user object
            user = User(user_id=user_id, email=email, name=name, groups=groups)
            
            # Check authorization
            if not user.is_authorized():
                flash('Access denied. You are not authorized to access this application.', 'error')
                return redirect(url_for('auth.unauthorized'))
            
            # Store user data in session
            session['user_data'] = {
                'id': user_id,
                'email': email,
                'name': name,
                'groups': groups
            }
            session['user_id'] = user_id
            
            # Log in user
            login_user(user)
            
            logger.info(f"User {email} logged in successfully via SAML")
            flash(f'Welcome, {name}!', 'success')
            
            return redirect(url_for('index'))
        else:
            logger.error(f"SAML errors: {errors}")
            flash('SAML authentication failed', 'error')
            return redirect(url_for('auth.login'))
            
    except Exception as e:
        logger.error(f"SAML ACS error: {e}")
        flash('SAML authentication failed', 'error')
        return redirect(url_for('auth.login'))

@auth_bp.route('/logout')
@login_required
def logout():
    """Logout route"""
    user_email = current_user.email if current_user.is_authenticated else 'Unknown'
    logout_user()
    session.clear()
    logger.info(f"User {user_email} logged out")
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/unauthorized')
def unauthorized():
    """Unauthorized access page"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Access Denied</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 50px; text-align: center; }
            .error { color: red; }
        </style>
    </head>
    <body>
        <h1 class="error">Access Denied</h1>
        <p>You are not authorized to access this application.</p>
        <p>Please contact your administrator if you believe this is an error.</p>
        <a href="/auth/logout">Logout</a>
    </body>
    </html>
    ''', 403

def init_saml_auth(req):
    """Initialize SAML auth object"""
    saml_settings = {
        'sp': {
            'entityId': os.getenv('SAML_SP_ENTITY_ID'),
            'assertionConsumerService': {
                'url': os.getenv('SAML_SP_ASSERTION_CONSUMER_SERVICE_URL'),
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
            },
            'NameIDFormat': 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'x509cert': '',
            'privateKey': ''
        },
        'idp': {
            'entityId': os.getenv('SAML_IDP_ENTITY_ID'),
            'singleSignOnService': {
                'url': os.getenv('SAML_IDP_SSO_URL'),
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            },
            'x509cert': os.getenv('SAML_IDP_X509_CERT')
        }
    }
    
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    return auth

def init_saml_req(request):
    """Convert Flask request to format expected by python3-saml"""
    url_data = request.url.split('?')
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.headers.get('Host', ''),
        'server_port': request.environ.get('SERVER_PORT', ''),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy()
    }
