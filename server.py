import os
import jwt
import uuid
import re
import datetime
import logging
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import resend
from email_validator import validate_email, EmailNotValidError

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET', 'dev-secret-key-change-in-production')

# Configure CORS
CORS(app, origins=[
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5000',
    'https://your-frontend-domain.com'
])

# Configure Resend
RESEND_API_KEY = os.getenv('RESEND_API_KEY')
if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY
    logger.info("✅ Resend API key configured")
else:
    logger.warning("❌ RESEND_API_KEY not set")

# Email configuration
SENDER_EMAIL = "onboarding@resend.dev"

# JWT Configuration
JWT_SECRET = os.getenv('JWT_SECRET', 'jwt-secret-key')
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 1

# Database
users_db = {}
refresh_tokens_db = {}
rate_limit_db = {}

# Rate limits
RATE_LIMITS = {
    'register': {'limit': 3, 'window': 60},
    'login_user': {'limit': 10, 'window': 60},
    'login_admin': {'limit': 3, 'window': 60},
    'resend_verification': {'limit': 3, 'window': 3600},
    'password_reset': {'limit': 3, 'window': 60},
    'refresh_token': {'limit': 10, 'window': 60},
    'delete_user': {'limit': 3, 'window': 60},
}

# ============================================
# Create sample users on startup
# ============================================
def create_sample_users():
    """Create sample users if they don't exist"""
    
    # Admin 1: Backend Developer
    if not any(user.get('email') == 'backend@uptorps.com' for user in users_db.values()):
        admin1_uuid = str(uuid.uuid4())
        users_db[admin1_uuid] = {
            'uuid': admin1_uuid,
            'email': 'backend@uptorps.com',
            'username': 'backenddev',
            'password': generate_password_hash('Admin123!@#'),
            'first_name': 'Backend',
            'last_name': 'Developer',
            'role': 'Admin',
            'admin_type': 'Developer',
            'dev_specialization': 'Backend',
            'is_active': True,
            'email_verified': True,
            'date_joined': datetime.datetime.utcnow().isoformat() + 'Z',
            'wallet_state': 'ACTIVE',
            'wallet_balance': 1000
        }
        logger.info("✅ Admin created: backend@uptorps.com / Admin123!@#")
    
    # Admin 2: Manager
    if not any(user.get('email') == 'admin@uptorps.com' for user in users_db.values()):
        admin2_uuid = str(uuid.uuid4())
        users_db[admin2_uuid] = {
            'uuid': admin2_uuid,
            'email': 'admin@uptorps.com',
            'username': 'admin01',
            'password': generate_password_hash('Admin123!@#'),
            'first_name': 'Admin',
            'last_name': 'User',
            'role': 'Admin',
            'admin_type': 'Manager',
            'dev_specialization': None,
            'is_active': True,
            'email_verified': True,
            'date_joined': datetime.datetime.utcnow().isoformat() + 'Z',
            'wallet_state': 'ACTIVE',
            'wallet_balance': 500
        }
        logger.info("✅ Admin created: admin@uptorps.com / Admin123!@#")
    
    # ===== NEW: Tutor User =====
    if not any(user.get('email') == 'tutor@uptorps.com' for user in users_db.values()):
        tutor_uuid = str(uuid.uuid4())
        users_db[tutor_uuid] = {
            'uuid': tutor_uuid,
            'email': 'tutor@uptorps.com',
            'username': 'tutor01',
            'password': generate_password_hash('Tutor123!@#'),
            'first_name': 'Tutor',
            'last_name': 'User',
            'role': 'Tutor',  # Tutor role
            'admin_type': None,
            'dev_specialization': None,
            'is_active': True,
            'email_verified': True,
            'date_joined': datetime.datetime.utcnow().isoformat() + 'Z',
            'wallet_state': 'ACTIVE',
            'wallet_balance': 750.50
        }
        logger.info("✅ Tutor created: tutor@uptorps.com / Tutor123!@#")
    
    # Regular student
    if not any(user.get('email') == 'student@example.com' for user in users_db.values()):
        student_uuid = str(uuid.uuid4())
        users_db[student_uuid] = {
            'uuid': student_uuid,
            'email': 'student@example.com',
            'username': 'student1',
            'password': generate_password_hash('Student123!@#'),
            'first_name': 'John',
            'last_name': 'Doe',
            'role': 'Student',
            'admin_type': None,
            'dev_specialization': None,
            'is_active': True,
            'email_verified': True,
            'date_joined': datetime.datetime.utcnow().isoformat() + 'Z',
            'wallet_state': 'ACTIVE',
            'wallet_balance': 450.75
        }
        logger.info("✅ Student created: student@example.com / Student123!@#")

# Create users immediately
create_sample_users()

# ============================================
# DEBUG ENDPOINTS
# ============================================

@app.route('/api/debug/status', methods=['GET'])
def debug_status():
    """Check if debug endpoints are working"""
    return jsonify({
        'status': 'debug endpoints working',
        'users_in_db': len(users_db),
        'timestamp': datetime.datetime.utcnow().isoformat()
    })

@app.route('/api/debug/users', methods=['GET'])
def debug_users():
    """List all users"""
    users_list = []
    for user_uuid, user in users_db.items():
        users_list.append({
            'uuid': user_uuid,
            'email': user['email'],
            'username': user['username'],
            'role': user['role'],
            'admin_type': user.get('admin_type'),
            'dev_specialization': user.get('dev_specialization')
        })
    return jsonify({
        'total_users': len(users_list),
        'users': users_list
    })

@app.route('/api/debug/login-test', methods=['POST'])
def debug_login_test():
    """Test login directly"""
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400
    
    # Find user
    user = None
    for u in users_db.values():
        if u['email'].lower() == email.lower():
            user = u
            break
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Check password
    if check_password_hash(user['password'], password):
        return jsonify({
            'success': True,
            'message': 'Password correct',
            'user': {
                'email': user['email'],
                'role': user['role'],
                'admin_type': user.get('admin_type'),
                'dev_specialization': user.get('dev_specialization')
            }
        })
    else:
        return jsonify({
            'success': False,
            'message': 'Password incorrect'
        }), 401

def generate_tokens(user_uuid):
    """Generate access and refresh tokens"""
    access_payload = {
        'user_uuid': user_uuid,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        'type': 'access',
        'iat': datetime.datetime.utcnow()
    }
    access_token = jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    refresh_payload = {
        'user_uuid': user_uuid,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        'type': 'refresh',
        'jti': str(uuid.uuid4()),
        'iat': datetime.datetime.utcnow()
    }
    refresh_token = jwt.encode(refresh_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    refresh_tokens_db[refresh_payload['jti']] = {
        'user_uuid': user_uuid,
        'expires': refresh_payload['exp'].isoformat(),
        'active': True
    }
    
    return access_token, refresh_token

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def check_rate_limit(identifier, limit_type):
    """Check rate limit for an identifier"""
    now = datetime.datetime.utcnow()
    limit_config = RATE_LIMITS.get(limit_type)
    
    if not limit_config:
        return True, 0
    
    key = f"{limit_type}:{identifier}"
    
    if key not in rate_limit_db:
        rate_limit_db[key] = []
    
    rate_limit_db[key] = [
        ts for ts in rate_limit_db[key] 
        if (now - ts).total_seconds() < limit_config['window']
    ]
    
    if len(rate_limit_db[key]) >= limit_config['limit']:
        oldest = rate_limit_db[key][0]
        wait_time = limit_config['window'] - (now - oldest).total_seconds()
        return False, round(wait_time)
    
    rate_limit_db[key].append(now)
    return True, 0

def send_verification_email(email, username, token):
    """Send email verification link"""
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:5173')
    verification_link = f"{frontend_url}/auth?mode=verify&token={token}"
    
    logger.info(f"📧 Sending verification email to: {email}")
    
    try:
        params = {
            "from": f"Uptorps <{SENDER_EMAIL}>",
            "to": [email],
            "subject": "Verify your email for Uptorps",
            "html": f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Verify Your Email</title>
            </head>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center;">
                    <h1 style="color: #56761A;">Uptorps</h1>
                    <h2>Welcome, {username}!</h2>
                    <p>Click the button below to verify your email:</p>
                    <a href="{verification_link}" style="display: inline-block; background-color: #56761A; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0;">Verify Email</a>
                    <p>This link expires in 30 minutes.</p>
                </div>
            </body>
            </html>
            """
        }
        
        email_response = resend.Emails.send(params)
        logger.info(f"✅ Email sent: {email_response.get('id')}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to send email: {str(e)}")
        return False

def send_password_reset_email(email, username, token):
    """Send password reset email"""
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:5173')
    reset_link = f"{frontend_url}/auth?mode=reset&token={token}"
    
    logger.info(f"📧 Sending password reset email to: {email}")
    
    try:
        params = {
            "from": f"Uptorps <{SENDER_EMAIL}>",
            "to": [email],
            "subject": "Reset your Uptorps password",
            "html": f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <title>Reset Your Password</title>
            </head>
            <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center;">
                    <h1 style="color: #56761A;">Uptorps</h1>
                    <h2>Hi {username}!</h2>
                    <p>Click the button below to reset your password:</p>
                    <a href="{reset_link}" style="display: inline-block; background-color: #56761A; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0;">Reset Password</a>
                    <p>This link expires in 30 minutes.</p>
                </div>
            </body>
            </html>
            """
        }
        
        email_response = resend.Emails.send(params)
        logger.info(f"✅ Password reset email sent: {email_response.get('id')}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to send password reset email: {str(e)}")
        return False

def token_required(f):
    """Decorator to require valid access token"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'detail': 'Authentication required'}), 401
        
        token = auth_header.replace('Bearer ', '')
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            if payload.get('type') != 'access':
                return jsonify({'detail': 'Invalid token type'}), 401
            
            request.user_uuid = payload['user_uuid']
        except jwt.ExpiredSignatureError:
            return jsonify({'detail': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'detail': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'detail': 'Authentication required'}), 401
        
        token = auth_header.replace('Bearer ', '')
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user = users_db.get(payload['user_uuid'])
            
            if not user or user.get('role') != 'Admin':
                return jsonify({'detail': 'Admin access required'}), 403
            
            request.user_uuid = payload['user_uuid']
            request.user = user
        except jwt.ExpiredSignatureError:
            return jsonify({'detail': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'detail': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

def tutor_required(f):
    """Decorator to require tutor role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'detail': 'Authentication required'}), 401
        
        token = auth_header.replace('Bearer ', '')
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user = users_db.get(payload['user_uuid'])
            
            if not user or user.get('role') not in ['Tutor', 'Admin']:
                return jsonify({'detail': 'Tutor access required'}), 403
            
            request.user_uuid = payload['user_uuid']
            request.user = user
        except jwt.ExpiredSignatureError:
            return jsonify({'detail': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'detail': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

def backend_dev_required(f):
    """Decorator to require backend developer role"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'detail': 'Authentication required'}), 401
        
        token = auth_header.replace('Bearer ', '')
        
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            user = users_db.get(payload['user_uuid'])
            
            if not user or user.get('role') != 'Admin' or user.get('admin_type') != 'Developer' or user.get('dev_specialization') != 'Backend':
                return jsonify({'detail': 'Backend developer access required'}), 403
            
            request.user_uuid = payload['user_uuid']
            request.user = user
        except jwt.ExpiredSignatureError:
            return jsonify({'detail': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'detail': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

# ==================== ROOT ENDPOINT ====================

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'message': 'Uptorps API is running!',
        'version': '1.0.0',
        'status': 'online',
        'users_in_db': len(users_db)
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.datetime.utcnow().isoformat()
    })

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.route('/api/accounts/register/', methods=['POST'])
def register():
    """Register a new user"""
    # Rate limiting
    client_ip = request.remote_addr
    allowed, wait_time = check_rate_limit(client_ip, 'register')
    if not allowed:
        return jsonify({'detail': f'Request was throttled. Expected available in {wait_time} seconds.'}), 429
    
    data = request.json
    
    # Validate required fields
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({'detail': f'{field} is required'}), 400
    
    # Validate email
    try:
        valid = validate_email(data['email'])
        email = valid.email
    except EmailNotValidError as e:
        return jsonify({'detail': str(e)}), 400
    
    # Validate password
    valid_password, password_message = validate_password(data['password'])
    if not valid_password:
        return jsonify({'detail': password_message}), 400
    
    # Check if user exists
    email_lower = data['email'].lower()
    username_lower = data['username'].lower()
    
    for user in users_db.values():
        if user['email'].lower() == email_lower:
            return jsonify({'detail': 'User with this email already exists'}), 400
        if user['username'].lower() == username_lower:
            return jsonify({'detail': 'Username already taken'}), 400
    
    # Create new user
    user_uuid = str(uuid.uuid4())
    user_data = {
        'uuid': user_uuid,
        'email': data['email'],
        'username': data['username'],
        'password': generate_password_hash(data['password']),
        'first_name': data.get('first_name', ''),
        'last_name': data.get('last_name', ''),
        'role': 'Student',  # Default role is Student
        'admin_type': None,
        'dev_specialization': None,
        'is_active': False,
        'email_verified': False,
        'date_joined': datetime.datetime.utcnow().isoformat() + 'Z',
        'wallet_state': 'INACTIVE',
        'wallet_balance': 0,
        'referral_code': data['username'].upper()
    }
    
    users_db[user_uuid] = user_data
    
    # Generate verification token
    verification_token = jwt.encode({
        'user_uuid': user_uuid,
        'email': data['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'type': 'email_verification'
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Send verification email
    email_sent = send_verification_email(data['email'], data['username'], verification_token)
    
    return jsonify({
        'message': 'User created',
        'verification_email_sent': email_sent
    }), 201

@app.route('/api/accounts/login/', methods=['POST'])
def login():
    """User login"""
    data = request.json
    
    if 'email' not in data or 'password' not in data:
        return jsonify({'detail': 'Email and password are required'}), 400
    
    # Find user
    user = None
    for u in users_db.values():
        if u['email'].lower() == data['email'].lower():
            user = u
            break
    
    if not user:
        return jsonify({'detail': 'Invalid credentials'}), 401
    
    # Check rate limit
    limit_type = 'login_admin' if user.get('role') == 'Admin' else 'login_user'
    allowed, wait_time = check_rate_limit(data['email'], limit_type)
    if not allowed:
        return jsonify({'detail': f'Request was throttled. Expected available in {wait_time} seconds.'}), 429
    
    # Verify password
    if not check_password_hash(user['password'], data['password']):
        return jsonify({'detail': 'Invalid credentials'}), 401
    
    # Check email verification
    if not user['email_verified']:
        return jsonify({'detail': 'Email not verified'}), 401
    
    # Generate tokens
    access_token, refresh_token = generate_tokens(user['uuid'])
    
    logger.info(f"User logged in: {user['email']} (Role: {user['role']})")
    
    # Return full user data
    return jsonify({
        'access': access_token,
        'refresh': refresh_token,
        'user': {
            'uuid': user['uuid'],
            'email': user['email'],
            'username': user['username'],
            'first_name': user.get('first_name', ''),
            'last_name': user.get('last_name', ''),
            'role': user['role'],
            'admin_type': user.get('admin_type'),
            'dev_specialization': user.get('dev_specialization'),
            'is_active': user['is_active'],
            'email_verified': user['email_verified'],
            'date_joined': user['date_joined']
        }
    }), 200

# ==================== OTHER ENDPOINTS ====================

@app.route('/api/accounts/verify-email/', methods=['POST'])
def verify_email():
    """Verify user email"""
    data = request.json
    
    if 'token' not in data:
        return jsonify({'detail': 'Token is required'}), 400
    
    try:
        payload = jwt.decode(data['token'], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        if payload.get('type') != 'email_verification':
            return jsonify({'detail': 'Invalid token type'}), 400
        
        user = users_db.get(payload['user_uuid'])
        
        if not user:
            return jsonify({'detail': 'User not found'}), 404
        
        if user['email_verified']:
            return jsonify({'detail': 'Email already verified'}), 400
        
        user['email_verified'] = True
        user['is_active'] = True
        
        return jsonify({'detail': 'Email verified successfully'}), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'detail': 'Verification token has expired'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'detail': 'Invalid verification token'}), 400

@app.route('/api/accounts/resend-verification/', methods=['POST'])
def resend_verification():
    """Resend verification email"""
    data = request.json
    
    if 'email' not in data:
        return jsonify({'detail': 'Email is required'}), 400
    
    allowed, wait_time = check_rate_limit(data['email'], 'resend_verification')
    if not allowed:
        return jsonify({'detail': f'Request was throttled. Expected available in {wait_time} seconds.'}), 429
    
    user = None
    for u in users_db.values():
        if u['email'].lower() == data['email'].lower():
            user = u
            break
    
    if not user or user['email_verified']:
        return jsonify({'detail': 'If the email exists, a verification link was sent.'}), 200
    
    verification_token = jwt.encode({
        'user_uuid': user['uuid'],
        'email': user['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'type': 'email_verification'
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    send_verification_email(user['email'], user['username'], verification_token)
    
    return jsonify({'detail': 'If the email exists, a verification link was sent.'}), 200

@app.route('/api/accounts/refresh/', methods=['POST'])
def refresh_token():
    """Refresh access token"""
    data = request.json
    
    if 'refresh' not in data:
        return jsonify({'detail': 'Refresh token is required'}), 400
    
    allowed, wait_time = check_rate_limit(request.remote_addr, 'refresh_token')
    if not allowed:
        return jsonify({'detail': f'Request was throttled. Expected available in {wait_time} seconds.'}), 429
    
    try:
        payload = jwt.decode(data['refresh'], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        if payload.get('type') != 'refresh':
            return jsonify({'detail': 'Invalid token type'}), 401
        
        jti = payload.get('jti')
        if jti and jti in refresh_tokens_db and not refresh_tokens_db[jti].get('active', True):
            return jsonify({'detail': 'Token has been revoked'}), 401
        
        access_token, new_refresh_token = generate_tokens(payload['user_uuid'])
        
        if jti and jti in refresh_tokens_db:
            refresh_tokens_db[jti]['active'] = False
        
        return jsonify({
            'access': access_token,
            'refresh': new_refresh_token
        }), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'detail': 'Refresh token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'detail': 'Invalid refresh token'}), 401

@app.route('/api/accounts/users/<uuid:user_uuid>/delete/', methods=['DELETE'])
@admin_required
def delete_user(user_uuid):
    """Delete user account"""
    user_uuid = str(user_uuid)
    
    allowed, wait_time = check_rate_limit(request.user_uuid, 'delete_user')
    if not allowed:
        return jsonify({'detail': f'Request was throttled. Expected available in {wait_time} seconds.'}), 429
    
    if user_uuid not in users_db:
        return jsonify({'detail': 'User not found'}), 404
    
    if user_uuid == request.user_uuid:
        return jsonify({'detail': 'Admin cannot delete themselves'}), 400
    
    deleted_user = users_db.pop(user_uuid)
    logger.info(f"User deleted: {deleted_user['email']}")
    
    return '', 204

@app.route('/api/accounts/password-reset/', methods=['POST'])
def password_reset_request():
    """Request password reset"""
    data = request.json
    
    if 'email' not in data:
        return jsonify({'detail': 'Email is required'}), 400
    
    allowed, wait_time = check_rate_limit(data['email'], 'password_reset')
    if not allowed:
        return jsonify({'detail': f'Request was throttled. Expected available in {wait_time} seconds.'}), 429
    
    user = None
    for u in users_db.values():
        if u['email'].lower() == data['email'].lower():
            user = u
            break
    
    if not user:
        return jsonify({'detail': 'If the email exists, a reset link was sent.'}), 200
    
    reset_token = jwt.encode({
        'user_uuid': user['uuid'],
        'email': user['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'type': 'password_reset'
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    send_password_reset_email(user['email'], user['username'], reset_token)
    
    return jsonify({'detail': 'If the email exists, a reset link was sent.'}), 200

@app.route('/api/accounts/password-reset/confirm/', methods=['POST'])
def password_reset_confirm():
    """Confirm password reset"""
    data = request.json
    
    if 'token' not in data or 'new_password' not in data:
        return jsonify({'detail': 'Token and new_password are required'}), 400
    
    valid_password, password_message = validate_password(data['new_password'])
    if not valid_password:
        return jsonify({'detail': password_message}), 400
    
    try:
        payload = jwt.decode(data['token'], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        if payload.get('type') != 'password_reset':
            return jsonify({'detail': 'Invalid token type'}), 400
        
        user = users_db.get(payload['user_uuid'])
        
        if not user:
            return jsonify({'detail': 'User not found'}), 404
        
        user['password'] = generate_password_hash(data['new_password'])
        
        return jsonify({'detail': 'Password reset successful'}), 200
        
    except jwt.ExpiredSignatureError:
        return jsonify({'detail': 'Reset token has expired'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'detail': 'Invalid reset token'}), 400

@app.route('/api/accounts/users/info/<uuid:user_uuid>/', methods=['GET', 'PATCH', 'PUT'])
@token_required
def user_info(user_uuid):
    """Get or update user information"""
    user_uuid = str(user_uuid)
    
    if user_uuid not in users_db:
        return jsonify({'detail': 'User not found'}), 404
    
    target_user = users_db[user_uuid]
    current_user = users_db[request.user_uuid]
    
    if request.user_uuid != user_uuid and current_user.get('role') != 'Admin':
        return jsonify({'detail': 'Cannot view this user\'s profile'}), 403
    
    if request.method == 'GET':
        user_data = {
            'uuid': target_user['uuid'],
            'email': target_user['email'],
            'username': target_user['username'],
            'first_name': target_user['first_name'],
            'last_name': target_user['last_name'],
            'role': target_user['role'],
            'is_active': target_user['is_active'],
            'email_verified': target_user['email_verified'],
            'date_joined': target_user['date_joined']
        }
        
        if current_user.get('role') == 'Admin':
            user_data['admin_type'] = target_user.get('admin_type')
            user_data['dev_specialization'] = target_user.get('dev_specialization')
        
        return jsonify(user_data), 200
    
    elif request.method in ['PATCH', 'PUT']:
        data = request.json
        
        editable_fields = ['username', 'first_name', 'last_name']
        
        if current_user.get('role') == 'Admin':
            editable_fields.extend(['email', 'role', 'admin_type', 'dev_specialization'])
        
        for field in editable_fields:
            if field in data:
                if field == 'role' and data['role'] not in ['Student', 'Tutor', 'Admin']:
                    continue
                if field == 'admin_type' and data.get('admin_type') not in [None, 'Manager', 'Developer']:
                    continue
                if field == 'dev_specialization' and data.get('dev_specialization') not in [None, 'Frontend', 'Backend', 'Security']:
                    continue
                
                target_user[field] = data[field]
        
        return jsonify({'detail': 'User updated successfully'}), 200

@app.route('/api/accounts/create-admin/', methods=['POST'])
@backend_dev_required
def create_admin():
    """Create admin account"""
    data = request.json
    
    required_fields = ['email', 'username', 'password', 'role', 'admin_type']
    for field in required_fields:
        if field not in data:
            return jsonify({'detail': f'{field} is required'}), 400
    
    if data['role'] != 'Admin':
        return jsonify({'detail': 'Role must be "Admin"'}), 400
    
    if data['admin_type'] not in ['Manager', 'Developer']:
        return jsonify({'detail': 'admin_type must be "Manager" or "Developer"'}), 400
    
    if data['admin_type'] == 'Developer' and 'dev_specialization' not in data:
        return jsonify({'detail': 'dev_specialization is required for Developer role'}), 400
    
    try:
        valid = validate_email(data['email'])
        email = valid.email
    except EmailNotValidError as e:
        return jsonify({'detail': str(e)}), 400
    
    valid_password, password_message = validate_password(data['password'])
    if not valid_password:
        return jsonify({'detail': password_message}), 400
    
    email_lower = data['email'].lower()
    username_lower = data['username'].lower()
    
    for user in users_db.values():
        if user['email'].lower() == email_lower:
            return jsonify({'detail': 'User with this email already exists'}), 400
        if user['username'].lower() == username_lower:
            return jsonify({'detail': 'Username already taken'}), 400
    
    admin_uuid = str(uuid.uuid4())
    users_db[admin_uuid] = {
        'uuid': admin_uuid,
        'email': data['email'],
        'username': data['username'],
        'password': generate_password_hash(data['password']),
        'first_name': data.get('first_name', ''),
        'last_name': data.get('last_name', ''),
        'role': 'Admin',
        'admin_type': data['admin_type'],
        'dev_specialization': data.get('dev_specialization'),
        'is_active': True,
        'email_verified': True,
        'date_joined': datetime.datetime.utcnow().isoformat() + 'Z',
        'wallet_state': 'ACTIVE',
        'wallet_balance': 0
    }
    
    return jsonify({
        'message': 'Admin account created successfully',
        'user_uuid': admin_uuid
    }), 201

# Print startup info
logger.info("\n" + "="*60)
logger.info("🚀 Uptorps API Server Started!")
logger.info(f"📍 Environment: {'Production' if os.getenv('RENDER') else 'Development'}")
logger.info(f"📧 Email From: {SENDER_EMAIL}")
logger.info("👑 Admin Users:")
logger.info("   - backend@uptorps.com / Admin123!@# (Developer - Backend)")
logger.info("   - admin@uptorps.com / Admin123!@# (Manager)")
logger.info("🧑‍🏫 Tutor User:")
logger.info("   - tutor@uptorps.com / Tutor123!@#")
logger.info("🧑 Student User:")
logger.info("   - student@example.com / Student123!@#")
logger.info(f"📊 Total Users: {len(users_db)}")
logger.info("="*60 + "\n")

if __name__ == '__main__':
    app.run(debug=True, port=5000)