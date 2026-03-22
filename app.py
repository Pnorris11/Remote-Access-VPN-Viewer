import requests
import os
import time
import threading
import logging
import uuid
import json
import jwt
import base64
from flask import Flask, render_template, jsonify, request, redirect, url_for, session, send_from_directory
from markupsafe import escape
from datetime import datetime, timedelta
from auth import init_auth, require_auth
from flask_login import current_user, login_user, UserMixin, LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO, emit
from dotenv import load_dotenv
import urllib3
from werkzeug.middleware.proxy_fix import ProxyFix

# Suppress InsecureRequestWarning for cleaner logs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
load_dotenv()

# Check if running in debug mode
DEBUG_MODE = os.getenv('DEBUG_MODE', 'False').lower() == 'true'

# Configure SSL verification from environment variable
# Supports: 'True', 'False', or a path to a CA bundle file
ssl_verify_env = os.getenv('SSL_VERIFY', 'True')
if ssl_verify_env.lower() == 'false':
    SSL_VERIFY = False
elif ssl_verify_env.lower() == 'true':
    SSL_VERIFY = True
else:
    # Assume it's a path to a CA bundle file
    SSL_VERIFY = ssl_verify_env

# Set up logging to show Process ID (PID)
log_level = logging.INFO if DEBUG_MODE else logging.ERROR
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - PID:%(process)d - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

if DEBUG_MODE:
    logger.info("🔧 DEBUG MODE ENABLED - Running without authentication and HTTPS requirements")

app = Flask(__name__)

# Configure app for reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# --- App Configuration & Auth Init ---
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = False if DEBUG_MODE else True  # Allow HTTP in debug mode
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['PREFERRED_URL_SCHEME'] = 'http' if DEBUG_MODE else 'https'
app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF tokens don't expire (session-based)
app.config['WTF_CSRF_SSL_STRICT'] = False if DEBUG_MODE else True  # Allow HTTP in debug mode

# Only initialize auth if not in debug mode
if not DEBUG_MODE:
    init_auth(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize SocketIO with CORS support for reverse proxy
socketio = SocketIO(
    app,
    cors_allowed_origins="*",  # Restrict this in production to your domain
    async_mode='threading',
    logger=True if DEBUG_MODE else False,  # Enable logging in debug mode
    engineio_logger=True if DEBUG_MODE else False,  # Enable engine.io logging in debug mode
    manage_session=False,  # Use Flask sessions instead of Socket.IO sessions
    cookie=f'{app.config["SESSION_COOKIE_NAME"]}_io' if 'SESSION_COOKIE_NAME' in app.config else 'io'  # Use separate cookie for SocketIO but share session
)

# Add User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_info):
        self.id = user_info.get('sub')
        self.email = user_info.get('email')
        self.username = user_info.get('preferred_username', user_info.get('email', 'Unknown'))
        self.name = user_info.get('name', self.username)
        self.groups = user_info.get('groups', [])
        self.user_info = user_info

    def get_id(self):
        return self.id
    
    def is_authorized(self):
        """Check if user is authorized to access the application"""
        # For now, return True for any authenticated user
        # You can add group-based authorization logic here if needed
        return True

# Add user loader for Flask-Login after init_auth
login_manager = LoginManager()
login_manager.init_app(app)  # Fix: Initialize login manager with app
login_manager.login_view = 'auth.login'  # Set login view for redirects

@login_manager.user_loader
def load_user(user_id):
    """Load user from session data"""
    if 'user_info' in session and session.get('authenticated'):
        user_info = session['user_info']
        if user_info.get('sub') == user_id:
            return User(user_info)
    return None

# Add function to check if user is authenticated
def is_user_authenticated():
    """Check if current user is authenticated"""
    # Always return True in debug mode
    if DEBUG_MODE:
        return True

    authenticated = (current_user.is_authenticated and
                    session.get('authenticated') == True and
                    'user_info' in session)
    logger.debug(f"Auth check: current_user.is_authenticated={current_user.is_authenticated}, "
                f"session.authenticated={session.get('authenticated')}, "
                f"user_info_in_session={'user_info' in session}, "
                f"final_result={authenticated}")
    return authenticated

# Decorator to optionally require auth (skips in debug mode)
def optional_auth(f):
    """Require authentication unless in debug mode"""
    if DEBUG_MODE:
        # In debug mode, just call the function directly
        return f
    else:
        # In production mode, require authentication
        return require_auth(f)

# --- Environment Variable Validation ---
def validate_env_vars():
    fmc_configs = []
    try:
        fmc_count = int(os.getenv('FMC_COUNT', 1))
        for i in range(1, fmc_count + 1):
            host, user, pw = os.getenv(f'FMC{i}_HOST'), os.getenv(f'FMC{i}_USERNAME'), os.getenv(f'FMC{i}_PASSWORD')
            name = os.getenv(f'FMC{i}_NAME', f'FMC{i}')  # Use env var or fallback to FMC{i}
            if not all([host, user, pw]):
                raise ValueError(f"Missing or empty env vars for FMC{i}")
            fmc_configs.append({'name': name, 'host': host, 'username': user, 'password': pw, 'token': None, 'token_expiry': None, 'domain_uuid': None})
    except (ValueError, TypeError) as e:
        logger.error(f"Invalid FMC configuration in .env file: {e}")
        raise SystemExit(f"Startup failed due to invalid config: {e}")
    return fmc_configs

def load_policy_mappings():
    """Loads group policy mappings from environment variables (e.g., POLICY_MAP_InternalName=DisplayName)"""
    mappings = {}
    prefix = 'POLICY_MAP_'
    for key, value in os.environ.items():
        if key.startswith(prefix):
            # Get the name after "POLICY_MAP_"
            internal_name = key[len(prefix):]
            mappings[internal_name] = value
    
    if mappings:
        logger.info(f"Loaded {len(mappings)} group policy name mappings.")
    else:
        logger.info("No group policy name mappings found in environment.")
    return mappings

# --- Globals and Locks ---
try:
    fmc_configs = validate_env_vars()
except SystemExit as e:
    exit(1)

policy_mappings = load_policy_mappings()
cached_sessions = []
last_refresh_time = None
session_lock = threading.Lock()
token_lock = threading.Lock()
refresh_lock = threading.Lock()
REFRESH_INTERVAL = 30  # Changed to 30 seconds

# --- Core FMC Functions ---

def get_fmc_token(config, run_id):
    with token_lock:
        if config['token'] and config['token_expiry'] and datetime.now() < config['token_expiry'] - timedelta(minutes=1):
            logger.info(f"[{run_id}] Reusing valid cached token for {config['name']}.")
            return config['token'], config['domain_uuid']
        url = f"https://{config['host']}/api/fmc_platform/v1/auth/generatetoken"
        try:
            response = requests.post(url, auth=(config['username'], config['password']), verify=SSL_VERIFY, timeout=10)
            if response.status_code == 204:
                token, domain_uuid = response.headers.get("X-auth-access-token"), response.headers.get("DOMAIN_UUID")
                if not token or not domain_uuid:
                    logger.error(f"[{run_id}] CRITICAL: Token or DOMAIN_UUID missing in response headers.")
                    return None, None
                expiry = datetime.now() + timedelta(minutes=30)
                config.update({'token': token, 'token_expiry': expiry, 'domain_uuid': domain_uuid})
                logger.info(f"[{run_id}] Token for {config['name']} fetched successfully.")
                return token, domain_uuid
            else:
                raise Exception(f"Auth failed with status {response.status_code}")
        except Exception as e:
            logger.error(f"[{run_id}] Exception during token fetch for {config['name']}: {e}")
            raise

def get_all_active_sessions(config, token, domain_uuid, run_id):
    """Fetch all active sessions with pagination support"""
    all_sessions = []
    offset = 0
    limit = 100  # Items per page (FMC supports up to 1000, but 100 is safer)

    while True:
        url = f"https://{config['host']}/api/fmc_config/v1/domain/{domain_uuid}/analysis/activesessions?offset={offset}&limit={limit}"
        headers = {"X-auth-access-token": token}

        logger.info(f"[{run_id}] Fetching sessions from {config['name']} (offset={offset}, limit={limit})")

        try:
            response = requests.get(url, headers=headers, verify=SSL_VERIFY, timeout=15)

            if response.status_code == 200:
                data = response.json()
                items = data.get("items", [])
                all_sessions.extend(items)

                # Check if there are more pages
                paging = data.get("paging", {})
                total = paging.get("count", 0)

                logger.info(f"[{run_id}] Retrieved {len(items)} sessions from {config['name']} (total so far: {len(all_sessions)}/{total})")

                # Break if we've retrieved all items or no items returned
                if len(all_sessions) >= total or len(items) == 0:
                    logger.info(f"[{run_id}] Completed fetching all sessions from {config['name']}: {len(all_sessions)} total")
                    break

                offset += limit
            else:
                logger.error(f"[{run_id}] Failed to get sessions from {config['name']}: {response.status_code} - {response.text}")
                break

        except Exception as e:
            logger.error(f"[{run_id}] Error fetching sessions from {config['name']} at offset {offset}: {e}")
            break

    return all_sessions

def get_user_activity_details(config, token, domain_uuid, username, login_time, run_id):
    """Fetch user activity details to get WAN IP and country information"""
    # Subtract 2 seconds from login_time as specified
    search_time = login_time - 2

    url = f"https://{config['host']}/api/fmc_config/v1/domain/{domain_uuid}/analysis/useractivity"
    headers = {"X-auth-access-token": token}
    params = {
        "offset": 0,
        "limit": 25,
        "time": f"after:{search_time}",
        "username": username
    }

    logger.info(f"[{run_id}] Fetching user activity for {username} from {config['name']} (time: after:{search_time})")

    try:
        response = requests.get(url, headers=headers, params=params, verify=SSL_VERIFY, timeout=15)

        if response.status_code == 200:
            data = response.json()
            items = data.get("items", [])

            # Find the VPN Login event matching the login time
            for item in items:
                if (item.get("event") == "VPN User Login" and
                    item.get("time") == login_time and
                    item.get("username") == username):

                    wan_ip = item.get("vpnClientPublicIP", "N/A")
                    country = item.get("vpnClientCountry", "N/A")

                    # Clean up the WAN IP (remove ::ffff: prefix for IPv4-mapped IPv6 addresses)
                    if wan_ip.startswith("::ffff:"):
                        wan_ip = wan_ip.replace("::ffff:", "")

                    # Capitalize country name
                    if country and country != "N/A":
                        country = country.title()

                    logger.info(f"[{run_id}] Found activity for {username}: WAN IP={wan_ip}, Country={country}")
                    return {"wan_ip": wan_ip, "country": country}

            logger.warning(f"[{run_id}] No matching VPN Login event found for {username} at time {login_time}")
            return {"wan_ip": "N/A", "country": "N/A"}
        else:
            logger.error(f"[{run_id}] Failed to get user activity from {config['name']}: {response.status_code}")
            return {"wan_ip": "N/A", "country": "N/A"}

    except Exception as e:
        logger.error(f"[{run_id}] Error fetching user activity from {config['name']}: {e}")
        return {"wan_ip": "N/A", "country": "N/A"}

def refresh_data():
    with refresh_lock:
        run_id = uuid.uuid4().hex[:8]
        logger.info(f"[{run_id}] Starting data refresh cycle.")
        new_sessions = []
        is_refresh_successful = False

        for config in fmc_configs:
            try:
                token, domain_uuid = get_fmc_token(config, run_id)
                if not token:
                    logger.error(f"[{run_id}] Could not get token for {config['name']}, skipping.")
                    continue

                # Use the new pagination function
                sessions = get_all_active_sessions(config, token, domain_uuid, run_id)

                if sessions:
                    is_refresh_successful = True
                    logger.info(f"[{run_id}] Processing {len(sessions)} total sessions from {config['name']}...")

                    for s in sessions:
                        auth_type = s.get('authenticationType', '').lower()
                        vpn_type = s.get('vpnSessionType', '').lower()
                        ip_address = s.get('currentIP', '')

                        if '.' in ip_address and ('vpn' in auth_type or 'anyconnect' in vpn_type or 'ssl' in vpn_type):
                            login_ts = s.get('loginTime', 0)
                            username = s.get('username', 'N/A')

                            # --- Apply Policy Mapping ---
                            # Get the original policy name from FMC
                            original_policy = s.get('vpnGroupPolicy', 'N/A')

                            # Find the mapped name, but default to the original name if no map is found
                            mapped_policy = policy_mappings.get(original_policy, original_policy)

                            # Fetch user activity details to get WAN IP and country
                            activity_details = get_user_activity_details(
                                config, token, domain_uuid, username, login_ts, run_id
                            )

                            new_sessions.append({
                                'fmc': config['name'],
                                'username': username,
                                'assigned_ip': ip_address,
                                'login_time': login_ts if login_ts else None,  # Send Unix timestamp for client-side conversion
                                'group_policy': mapped_policy,
                                'wan_ip': activity_details.get('wan_ip', 'N/A'),
                                'country': activity_details.get('country', 'N/A'),
                            })
                else:
                    logger.warning(f"[{run_id}] No sessions returned from {config['name']}")

            except Exception as e:
                logger.error(f"[{run_id}] Unhandled error refreshing {config['name']}: {e}")
        
        if is_refresh_successful:
            with session_lock:
                global cached_sessions, last_refresh_time
                cached_sessions = new_sessions
                last_refresh_time = datetime.now()

                # Calculate FMC counts while we have the lock
                fmc_counts = {config['name']: 0 for config in fmc_configs}
                for session_item in cached_sessions:
                    fmc_name = session_item.get('fmc', 'N/A')
                    if fmc_name in fmc_counts:
                        fmc_counts[fmc_name] += 1

                # Capture the refresh time while in lock
                refresh_time_iso = last_refresh_time.isoformat()
                sessions_copy = cached_sessions.copy()
                total = len(cached_sessions)

            logger.info(f"[{run_id}] Data refresh completed. Total IPv4 VPN sessions cached: {total}")

            # Emit WebSocket update to all connected clients
            try:
                socketio.emit('session_update', {
                    'sessions': sessions_copy,
                    'total_count': total,
                    'fmc_counts': fmc_counts,
                    'last_refresh': refresh_time_iso,
                    'timestamp': datetime.now().isoformat()
                }, namespace='/')
                logger.info(f"[{run_id}] WebSocket update emitted to all clients")
            except Exception as e:
                logger.error(f"[{run_id}] Failed to emit WebSocket update: {e}")
        else:
            logger.error(f"[{run_id}] Data refresh failed for all FMCs. Preserving stale cache.")

def background_refresh():
    while True:
        refresh_data()
        time.sleep(REFRESH_INTERVAL)

# --- Start Background Thread ---
# For gunicorn: Start thread immediately (gunicorn doesn't use reloader)
# For werkzeug dev server: Only start in child process (WERKZEUG_RUN_MAIN == "true")
werkzeug_run_main = os.environ.get("WERKZEUG_RUN_MAIN")

# Detect if running under gunicorn by checking if it's imported
try:
    import sys
    is_gunicorn = 'gunicorn' in sys.modules
except:
    is_gunicorn = False

logger.info(f"PID {os.getpid()}: WERKZEUG_RUN_MAIN={werkzeug_run_main}, is_gunicorn={is_gunicorn}")

# Start background thread if using gunicorn OR if werkzeug child process
if is_gunicorn or werkzeug_run_main == "true":
    threading.Thread(target=background_refresh, daemon=True).start()
    logger.info(f"Background refresh thread started in PID: {os.getpid()}")
else:
    logger.info(f"Skipping background thread in PID: {os.getpid()} (parent process)")

# --- WebSocket Event Handlers ---
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    try:
        # Skip auth check in debug mode
        if not DEBUG_MODE and not is_user_authenticated():
            logger.warning(f"Unauthorized WebSocket connection attempt")
            return False

        # Refresh session to keep it alive
        if not DEBUG_MODE and 'user_info' in session:
            session.modified = True
            session.permanent = True
            logger.debug(f"Session refreshed for WebSocket connection")

        # Get user email safely
        user_email = 'Debug User'
        if not DEBUG_MODE:
            try:
                if hasattr(current_user, 'email') and current_user.is_authenticated:
                    user_email = current_user.email
            except:
                pass

        logger.info(f"WebSocket client connected: {user_email}")

        # Send current data to newly connected client
        with session_lock:
            fmc_counts = {config['name']: 0 for config in fmc_configs}
            for session_item in cached_sessions:
                fmc_name = session_item.get('fmc', 'N/A')
                if fmc_name in fmc_counts:
                    fmc_counts[fmc_name] += 1

            emit('session_update', {
                'sessions': cached_sessions,
                'total_count': len(cached_sessions),
                'fmc_counts': fmc_counts,
                'last_refresh': last_refresh_time.isoformat() if last_refresh_time else None,
                'timestamp': datetime.now().isoformat()
            })

        return True
    except Exception as e:
        logger.error(f"Error in WebSocket connect handler: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    try:
        user_email = current_user.email if (not DEBUG_MODE and hasattr(current_user, 'email') and current_user.is_authenticated) else 'Debug User'
    except:
        user_email = 'Debug User'
    logger.info(f"WebSocket client disconnected: {user_email}")

@socketio.on('request_update')
def handle_request_update():
    """Handle manual update request from client"""
    try:
        # Skip auth check in debug mode
        if not DEBUG_MODE and not is_user_authenticated():
            logger.warning("Unauthorized update request")
            return

        # Refresh session to keep it alive on user activity
        if not DEBUG_MODE and 'user_info' in session:
            session.modified = True
            session.permanent = True
            logger.debug(f"Session refreshed for update request")

        try:
            user_email = current_user.email if (not DEBUG_MODE and hasattr(current_user, 'email') and current_user.is_authenticated) else 'Debug User'
        except:
            user_email = 'Debug User'

        logger.info(f"Manual update requested via WebSocket by: {user_email}")

        # Send current data immediately
        with session_lock:
            fmc_counts = {config['name']: 0 for config in fmc_configs}
            for session_item in cached_sessions:
                fmc_name = session_item.get('fmc', 'N/A')
                if fmc_name in fmc_counts:
                    fmc_counts[fmc_name] += 1

            emit('session_update', {
                'sessions': cached_sessions,
                'total_count': len(cached_sessions),
                'fmc_counts': fmc_counts,
                'last_refresh': last_refresh_time.isoformat() if last_refresh_time else None,
                'timestamp': datetime.now().isoformat()
            })
    except Exception as e:
        logger.error(f"Error in request_update handler: {e}")
        import traceback
        logger.error(traceback.format_exc())

# Add periodic session keepalive handler
@socketio.on('keepalive')
def handle_keepalive():
    """Handle keepalive ping from client to maintain session"""
    try:
        # Refresh session on keepalive
        if not DEBUG_MODE and 'user_info' in session:
            session.modified = True
            session.permanent = True
            logger.debug(f"Session refreshed via keepalive")

        # Send acknowledgment
        emit('keepalive_ack', {'timestamp': datetime.now().isoformat()})
    except Exception as e:
        logger.error(f"Error in keepalive handler: {e}")

# --- Flask Routes ---
@app.route('/')
@optional_auth
def index():
    from flask_wtf.csrf import generate_csrf
    search_term = request.args.get('username', '').strip()

    with session_lock:
        sessions_data = cached_sessions.copy()
        refresh_time = last_refresh_time

    # Get total session count before filtering
    total_session_count = len(sessions_data)

    # Initialize FMC user counts from configured FMCs (ensures all FMCs show even with 0 users)
    fmc_counts = {config['name']: 0 for config in fmc_configs}

    # Count actual sessions per FMC
    for session_item in sessions_data:
        fmc_name = session_item.get('fmc', 'N/A')
        if fmc_name in fmc_counts:
            fmc_counts[fmc_name] += 1

    # Store all sessions before filtering for client-side operations
    all_sessions_data = sessions_data.copy()

    # Filter sessions based on search term
    if search_term:
        logger.info(f"Filtering sessions for username: {search_term}")
        sessions_data = [s for s in sessions_data if search_term.lower() in s.get('username', '').lower()]

    # Sort sessions by username (alphabetically)
    sessions_data.sort(key=lambda s: s.get('username', '').lower())
    all_sessions_data.sort(key=lambda s: s.get('username', '').lower())

    # Create a fake user object for debug mode
    user_for_template = current_user if not DEBUG_MODE else type('obj', (object,), {'is_authenticated': True, 'name': 'Debug User', 'email': 'debug@localhost'})()

    return render_template('index.html', sessions=sessions_data, all_sessions=all_sessions_data, search_term=search_term, current_user=user_for_template, last_refresh=refresh_time, total_count=total_session_count, fmc_counts=fmc_counts, csrf_token=generate_csrf())

@app.route('/api/sessions')
@optional_auth
def api_sessions():
    with session_lock: return jsonify(cached_sessions)

@app.route('/api/refresh', methods=['POST'])
@optional_auth
def api_refresh():
    username = current_user.username if (not DEBUG_MODE and hasattr(current_user, 'username')) else 'Debug User'
    logger.info(f"On-demand refresh requested by user: {username}")
    try:
        refresh_data()
        with session_lock:
            return jsonify({
                'success': True,
                'message': 'Data refreshed successfully',
                'session_count': len(cached_sessions),
                'last_refresh': last_refresh_time.isoformat() if last_refresh_time else None
            })
    except Exception as e:
        logger.error(f"On-demand refresh failed: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# Add error handler for 404s to help debug auth issues
@app.errorhandler(404)
def not_found_error(error):
    logger.error(f"404 error for path: {request.path} - User-Agent: {request.headers.get('User-Agent', 'Unknown')}")
    return jsonify({'error': 'Not found', 'path': request.path}), 404

# Add route debugging
@app.before_request
def log_request_info():
    if request.path.startswith('/auth/'):
        logger.info(f"Auth request: {request.method} {request.path} from {request.remote_addr}")

# Add function to get OIDC public keys for token validation
def get_oidc_public_keys():
    """Fetch OIDC public keys for JWT validation"""
    try:
        issuer = os.getenv('OIDC_ISSUER', 'https://bandwidth.okta.com/oauth2/default')
        jwks_url = f"{issuer}/v1/keys"
        response = requests.get(jwks_url, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        logger.error(f"Failed to fetch OIDC public keys: {e}")
        return None

# Add function to validate JWT token
def validate_id_token(id_token):
    """Validate ID token signature and claims"""
    try:
        # Get OIDC configuration
        issuer = os.getenv('OIDC_ISSUER', 'https://bandwidth.okta.com/oauth2/default')
        client_id = os.getenv('OIDC_CLIENT_ID')

        # Decode token header to get key ID
        unverified_header = jwt.get_unverified_header(id_token)
        kid = unverified_header.get('kid')

        # Get public keys
        jwks = get_oidc_public_keys()
        if not jwks:
            logger.error("Could not fetch OIDC keys - authentication failed")
            raise ValueError("Unable to fetch OIDC public keys for token validation")

        # Find the correct public key
        public_key = None
        for key in jwks.get('keys', []):
            if key.get('kid') == kid:
                public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
                break

        if not public_key:
            logger.error(f"Could not find public key for kid: {kid} - authentication failed")
            raise ValueError(f"Public key not found for key ID: {kid}")

        # Validate the token
        decoded_token = jwt.decode(
            id_token,
            public_key,
            algorithms=['RS256'],
            audience=client_id,
            issuer=issuer,
            options={
                "verify_signature": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True
            }
        )

        logger.info("ID token signature validation successful")
        return decoded_token

    except jwt.ExpiredSignatureError:
        logger.error("ID token has expired")
        raise ValueError("Token has expired")
    except jwt.InvalidAudienceError:
        logger.error("ID token has invalid audience")
        raise ValueError("Invalid token audience")
    except jwt.InvalidIssuerError:
        logger.error("ID token has invalid issuer")
        raise ValueError("Invalid token issuer")
    except jwt.InvalidSignatureError:
        logger.error("ID token has invalid signature")
        raise ValueError("Invalid token signature")
    except Exception as e:
        logger.error(f"ID token validation failed: {e}")
        raise ValueError(f"Token validation error: {str(e)}")

# Add missing OIDC callback route
@app.route('/auth/callback')
@csrf.exempt  # Exempt from CSRF as this is called by external OIDC provider
def auth_callback():
    try:
        logger.info(f"OIDC callback received with args: {request.args}")
        logger.info(f"Current session keys: {list(session.keys())}")
        
        # Get the authorization code from the callback
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            logger.error(f"OAuth error received: {error}")
            return f"Authentication failed: {escape(error)}", 400
            
        if not code:
            logger.error("No authorization code received in callback")
            return "Authentication failed: No authorization code", 400
            
        # Check if user is already authenticated to avoid duplicate token exchanges
        if is_user_authenticated():
            logger.info("User already authenticated, redirecting to home")
            return redirect(url_for('index'))
        
        # Look for state in the session using the dynamic key format
        session_state_key = f'_state_oidc_{state}'
        if state and session_state_key not in session:
            logger.warning(f"State {state} not found in session keys: {list(session.keys())}")
            # Continue anyway for now to avoid blocking authentication
        
        # Clean up old OIDC state entries to prevent session bloat
        state_keys_to_remove = [k for k in session.keys() if k.startswith('_state_oidc_')]
        for key in state_keys_to_remove:
            session.pop(key, None)
        logger.info(f"Cleaned up {len(state_keys_to_remove)} old OIDC state entries")
        
        # Exchange authorization code for tokens
        token_url = f"{os.getenv('OIDC_ISSUER', 'https://bandwidth.okta.com/oauth2/default')}/v1/token"
        
        # Construct redirect URI based on current request
        if request.headers.get('X-Forwarded-Proto'):
            # Behind reverse proxy
            redirect_uri = f"https://{request.headers.get('X-Forwarded-Host', request.host)}/auth/callback"
        else:
            redirect_uri = url_for('auth_callback', _external=True)
        
        logger.info(f"Using redirect_uri: {redirect_uri}")
        
        token_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': os.getenv('OIDC_CLIENT_ID'),
            'client_secret': os.getenv('OIDC_CLIENT_SECRET')
        }
        
        logger.info(f"Exchanging code for tokens at: {token_url}")
        token_response = requests.post(token_url, data=token_data, timeout=10)
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.status_code} - {token_response.text}")
            return f"Authentication failed: Token exchange error", 400
            
        tokens = token_response.json()
        id_token = tokens.get('id_token')
        access_token = tokens.get('access_token')
        
        if not id_token:
            logger.error("No ID token received from token exchange")
            return "Authentication failed: No ID token", 400
            
        # Validate ID token and extract user info
        try:
            user_info = validate_id_token(id_token)
            logger.info(f"User authenticated: {user_info.get('email', user_info.get('sub', 'Unknown'))}")
            
            # Create User object for Flask-Login
            user = User(user_info)
            
            # Clear session completely and start fresh to avoid size issues
            session.clear()
            
            # Store minimal session data BEFORE login_user to ensure it's available
            session['user_info'] = {
                'email': user_info.get('email'),
                'name': user_info.get('name', user_info.get('preferred_username', 'Unknown')),
                'sub': user_info.get('sub')
            }
            session['access_token'] = access_token
            session['authenticated'] = True
            session.permanent = True
            
            # Log the user in with Flask-Login AFTER setting session data
            login_user(user, remember=True, duration=timedelta(hours=8))
            
            logger.info(f"User session created successfully for: {user.email}")
            logger.info(f"Session keys after login: {list(session.keys())}")
            logger.info(f"Current user authenticated: {current_user.is_authenticated}")
            logger.info(f"Final auth check: {is_user_authenticated()}")
            
            return redirect(url_for('index'))
            
        except ValueError as token_error:
            logger.error(f"ID token validation failed: {token_error}")
            return "Authentication failed: Invalid token", 400
        except Exception as token_error:
            logger.error(f"Error processing ID token: {token_error}")
            return "Authentication failed: Invalid token", 400
        
    except Exception as e:
        logger.error(f"Error in OIDC callback: {e}")
        return "Authentication failed: Server error", 500

# Add alternative route that bypasses auth decorator for testing
@app.route('/status')
def status():
    """Status endpoint to check authentication state"""
    return jsonify({
        'authenticated': is_user_authenticated(),
        'current_user_authenticated': current_user.is_authenticated,
        'session_authenticated': session.get('authenticated'),
        'user_info': session.get('user_info'),
        'session_keys': list(session.keys())
    })

# Add logout route
@app.route('/auth/logout')
def logout():
    logger.info(f"User logout requested: {getattr(current_user, 'email', 'Unknown')}")
    session.clear()
    return redirect(url_for('index'))

# Add favicon route
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'favicon.ico', mimetype='image/vnd.microsoft.icon')

# --- NEW ROUTE FOR LOGO ---
@app.route('/logo.png')
def logo():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                             'cisco_secure_client.png', mimetype='image/png')

# Add route for static images (redundant if only logo/favicon, but harmless)
@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(os.path.join(app.root_path, 'static'), filename)

# --- Main Application Entry Point ---
if __name__ == '__main__':
    # In debug mode, bind to all interfaces and enable debug logging
    if DEBUG_MODE:
        logger.info(f"Starting Flask app with SocketIO in DEBUG MODE (PID: {os.getpid()})")
        logger.info("🔧 Debug mode settings:")
        logger.info("  - Authentication: DISABLED")
        logger.info("  - HTTPS requirement: DISABLED")
        logger.info("  - Binding to: 0.0.0.0:5001 (accessible from network)")
        logger.info("  - WebSocket: Enabled over HTTP")
        socketio.run(app, host='0.0.0.0', port=5001, debug=False, use_reloader=True, allow_unsafe_werkzeug=True)
    else:
        logger.error(f"Starting Flask app with SocketIO in __main__ (PID: {os.getpid()})")
        # Bind only to localhost since nginx will proxy to us
        # Use socketio.run() instead of app.run() for WebSocket support
        socketio.run(app, host='127.0.0.1', port=5001, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
