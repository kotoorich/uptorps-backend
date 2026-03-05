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

# Configure CORS for your frontend domains
CORS(app, origins=[
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5000',
    'https://your-frontend-domain.com'  # Change to your actual frontend URL
])

# Configure Resend for email
RESEND_API_KEY = os.getenv('RESEND_API_KEY')
if not RESEND_API_KEY:
    logger.warning("RESEND_API_KEY not set in environment variables")
else:
    resend.api_key = RESEND_API_KEY
    logger.info("✅ Resend API key configured")

# ============================================
# FREE TEST DOMAIN - NO PAYMENT, NO DNS, NO VERIFICATION NEEDED!
# ============================================
SENDER_EMAIL = "onboarding@resend.dev"

# JWT Configuration
JWT_SECRET = os.getenv('JWT_SECRET', 'jwt-secret-key')
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 1

# Mock database (in production, use real database)
users_db = {}
refresh_tokens_db = {}
rate_limit_db = {}

# Rate limiting configuration
RATE_LIMITS = {
    'register': {'limit': 3, 'window': 60},
    'login_user': {'limit': 10, 'window': 60},
    'login_admin': {'limit': 3, 'window': 60},
    'resend_verification': {'limit': 3, 'window': 3600},
    'password_reset': {'limit': 3, 'window': 60},
    'refresh_token': {'limit': 10, 'window': 60},
    'delete_user': {'limit': 3, 'window': 60},
}

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
    """Send email verification link using Resend's FREE test domain"""
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:5173')
    verification_link = f"{frontend_url}/auth?mode=verify&token={token}"
    
    logger.info(f"📧 Attempting to send FREE verification email to: {email}")
    logger.info(f"🔗 Verification link: {verification_link}")
    
    try:
        params = {
            # USING RESEND'S FREE TEST DOMAIN - NO VERIFICATION NEEDED!
            "from": f"Uptorps <{SENDER_EMAIL}>",
            "to": [email],
            "subject": "Verify your email for Uptorps",
            "html": f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verify Your Email</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #56761A;">Uptorps</h1>
                </div>
                
                <div style="background-color: #f9f9f9; border-radius: 8px; padding: 30px; border: 1px solid #e0e0e0;">
                    <h2 style="color: #2C2C2C; margin-top: 0;">Welcome to Uptorps, {username}!</h2>
                    
                    <p style="color: #2C2C2C;">Thank you for signing up. Please verify your email address to activate your account and start your learning journey.</p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{verification_link}" style="background-color: #56761A; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Verify Email Address</a>
                    </div>
                    
                    <p style="color: #666; font-size: 14px;">This link will expire in 30 minutes for security reasons.</p>
                    
                    <p style="color: #666; font-size: 14px;">If you didn't create an account with Uptorps, you can safely ignore this email.</p>
                </div>
                
                <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
                    <p>© 2024 Uptorps. All rights reserved.</p>
                </div>
            </body>
            </html>
            """
        }
        
        email_response = resend.Emails.send(params)
        logger.info(f"✅ Email sent successfully! Response ID: {email_response.get('id')}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to send email: {str(e)}")
        logger.error(f"Error type: {type(e).__name__}")
        return False

def send_password_reset_email(email, username, token):
    """Send password reset email using Resend's FREE test domain"""
    frontend_url = os.getenv('FRONTEND_URL', 'http://localhost:5173')
    reset_link = f"{frontend_url}/auth?mode=reset&token={token}"
    
    logger.info(f"📧 Sending FREE password reset email to: {email}")
    
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
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Reset Your Password</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
                <div style="text-align: center; margin-bottom: 30px;">
                    <h1 style="color: #56761A;">Uptorps</h1>
                </div>
                
                <div style="background-color: #f9f9f9; border-radius: 8px; padding: 30px; border: 1px solid #e0e0e0;">
                    <h2 style="color: #2C2C2C; margin-top: 0;">Password Reset Request</h2>
                    
                    <p style="color: #2C2C2C;">Hi {username},</p>
                    
                    <p style="color: #2C2C2C;">We received a request to reset your password. Click the button below to create a new password:</p>
                    
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{reset_link}" style="background-color: #56761A; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reset Password</a>
                    </div>
                    
                    <p style="color: #666; font-size: 14px;">This link will expire in 30 minutes for security reasons.</p>
                    
                    <p style="color: #666; font-size: 14px;">If you didn't request a password reset, you can safely ignore this email.</p>
                </div>
                
                <div style="text-align: center; margin-top: 20px; color: #999; font-size: 12px;">
                    <p>© 2024 Uptorps. All rights reserved.</p>
                </div>
            </body>
            </html>
            """
        }
        
        email_response = resend.Emails.send(params)
        logger.info(f"✅ Password reset email sent! Response ID: {email_response.get('id')}")
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
        'message': 'Uptorps API is running with FREE email!',
        'version': '1.0.0',
        'status': 'online',
        'email_status': '✅ Using Resend FREE test domain - No payment needed!'
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
        'role': 'Student',
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
    
    # Generate verification token (30 minutes expiry)
    verification_token = jwt.encode({
        'user_uuid': user_uuid,
        'email': data['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'type': 'email_verification'
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Send verification email (FREE!)
    email_sent = send_verification_email(data['email'], data['username'], verification_token)
    
    logger.info(f"User registered: {data['email']}, Email sent: {email_sent}")
    
    return jsonify({
        'message': 'User created',
        'verification_email_sent': email_sent
    }), 201

@app.route('/api/accounts/verify-email/', methods=['POST'])
def verify_email():
    """Verify user email"""
    data = request.json
    
    if 'token' not in data:
        return jsonify({'detail': 'Token is required'}), 400
    
    try:
        # Decode token
        payload = jwt.decode(data['token'], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        if payload.get('type') != 'email_verification':
            return jsonify({'detail': 'Invalid token type'}), 400
        
        user = users_db.get(payload['user_uuid'])
        
        if not user:
            return jsonify({'detail': 'User not found'}), 404
        
        if user['email_verified']:
            return jsonify({'detail': 'Email already verified'}), 400
        
        # Verify email
        user['email_verified'] = True
        user['is_active'] = True
        
        logger.info(f"Email verified for user: {user['email']}")
        
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
    
    # Rate limiting
    allowed, wait_time = check_rate_limit(data['email'], 'resend_verification')
    if not allowed:
        return jsonify({'detail': f'Request was throttled. Expected available in {wait_time} seconds.'}), 429
    
    # Find user (case-insensitive)
    user = None
    for u in users_db.values():
        if u['email'].lower() == data['email'].lower():
            user = u
            break
    
    # Always return same message for security
    if not user or user['email_verified']:
        return jsonify({'detail': 'If the email exists, a verification link was sent.'}), 200
    
    # Generate new verification token
    verification_token = jwt.encode({
        'user_uuid': user['uuid'],
        'email': user['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'type': 'email_verification'
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Send verification email (FREE!)
    send_verification_email(user['email'], user['username'], verification_token)
    
    return jsonify({'detail': 'If the email exists, a verification link was sent.'}), 200

@app.route('/api/accounts/login/', methods=['POST'])
def login():
    """User login"""
    data = request.json
    
    if 'email' not in data or 'password' not in data:
        return jsonify({'detail': 'Email and password are required'}), 400
    
    # Find user (case-insensitive)
    user = None
    for u in users_db.values():
        if u['email'].lower() == data['email'].lower():
            user = u
            break
    
    if not user:
        return jsonify({'detail': 'Invalid credentials'}), 401
    
    # Check rate limit (different for admins)
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
    
    # Check if active
    if not user['is_active']:
        return jsonify({'detail': 'Account is inactive'}), 401
    
    # Generate tokens
    access_token, refresh_token = generate_tokens(user['uuid'])
    
    logger.info(f"User logged in: {user['email']}")
    
    return jsonify({
        'access': access_token,
        'refresh': refresh_token,
        'user': {
            'uuid': user['uuid'],
            'email': user['email'],
            'username': user['username'],
            'role': user['role'],
            'admin_type': user.get('admin_type'),
            'dev_specialization': user.get('dev_specialization'),
            'date_joined': user['date_joined']
        }
    }), 200

@app.route('/api/accounts/refresh/', methods=['POST'])
def refresh_token():
    """Refresh access token"""
    data = request.json
    
    if 'refresh' not in data:
        return jsonify({'detail': 'Refresh token is required'}), 400
    
    # Rate limiting
    allowed, wait_time = check_rate_limit(request.remote_addr, 'refresh_token')
    if not allowed:
        return jsonify({'detail': f'Request was throttled. Expected available in {wait_time} seconds.'}), 429
    
    try:
        # Decode refresh token
        payload = jwt.decode(data['refresh'], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        if payload.get('type') != 'refresh':
            return jsonify({'detail': 'Invalid token type'}), 401
        
        # Check if token is blacklisted
        jti = payload.get('jti')
        if jti and jti in refresh_tokens_db and not refresh_tokens_db[jti].get('active', True):
            return jsonify({'detail': 'Token has been revoked'}), 401
        
        # Generate new tokens (rotate)
        access_token, new_refresh_token = generate_tokens(payload['user_uuid'])
        
        # Blacklist old refresh token
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

@app.route('/api/accounts/create-admin/', methods=['POST'])
@backend_dev_required
def create_admin():
    """Create admin account"""
    data = request.json
    
    # Validate required fields
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
    
    if data.get('dev_specialization') and data['dev_specialization'] not in ['Frontend', 'Backend', 'Security']:
        return jsonify({'detail': 'dev_specialization must be "Frontend", "Backend", or "Security"'}), 400
    
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
    
    # Create admin user
    user_uuid = str(uuid.uuid4())
    user_data = {
        'uuid': user_uuid,
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
    
    users_db[user_uuid] = user_data
    
    logger.info(f"Admin account created: {data['email']}")
    
    return jsonify({
        'message': 'Admin account created successfully',
        'user_uuid': user_uuid
    }), 201

@app.route('/api/accounts/users/<uuid:user_uuid>/delete/', methods=['DELETE'])
@admin_required
def delete_user(user_uuid):
    """Delete user account"""
    user_uuid = str(user_uuid)
    
    # Rate limiting
    allowed, wait_time = check_rate_limit(request.user_uuid, 'delete_user')
    if not allowed:
        return jsonify({'detail': f'Request was throttled. Expected available in {wait_time} seconds.'}), 429
    
    # Check if user exists
    if user_uuid not in users_db:
        return jsonify({'detail': 'User not found'}), 404
    
    # Prevent admin from deleting themselves
    if user_uuid == request.user_uuid:
        return jsonify({'detail': 'Admin cannot delete themselves'}), 400
    
    # Delete user
    deleted_user = users_db.pop(user_uuid)
    logger.info(f"User deleted: {deleted_user['email']}")
    
    return '', 204

@app.route('/api/accounts/password-reset/', methods=['POST'])
def password_reset_request():
    """Request password reset"""
    data = request.json
    
    if 'email' not in data:
        return jsonify({'detail': 'Email is required'}), 400
    
    # Rate limiting
    allowed, wait_time = check_rate_limit(data['email'], 'password_reset')
    if not allowed:
        return jsonify({'detail': f'Request was throttled. Expected available in {wait_time} seconds.'}), 429
    
    # Find user (case-insensitive)
    user = None
    for u in users_db.values():
        if u['email'].lower() == data['email'].lower():
            user = u
            break
    
    # Always return same message for security
    if not user:
        return jsonify({'detail': 'If the email exists, a reset link was sent.'}), 200
    
    # Generate reset token (30 minutes)
    reset_token = jwt.encode({
        'user_uuid': user['uuid'],
        'email': user['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
        'type': 'password_reset'
    }, JWT_SECRET, algorithm=JWT_ALGORITHM)
    
    # Send password reset email (FREE!)
    send_password_reset_email(user['email'], user['username'], reset_token)
    
    return jsonify({'detail': 'If the email exists, a reset link was sent.'}), 200

@app.route('/api/accounts/password-reset/confirm/', methods=['POST'])
def password_reset_confirm():
    """Confirm password reset"""
    data = request.json
    
    if 'token' not in data or 'new_password' not in data:
        return jsonify({'detail': 'Token and new_password are required'}), 400
    
    # Validate new password
    valid_password, password_message = validate_password(data['new_password'])
    if not valid_password:
        return jsonify({'detail': password_message}), 400
    
    try:
        # Decode token
        payload = jwt.decode(data['token'], JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        if payload.get('type') != 'password_reset':
            return jsonify({'detail': 'Invalid token type'}), 400
        
        user = users_db.get(payload['user_uuid'])
        
        if not user:
            return jsonify({'detail': 'User not found'}), 404
        
        # Update password
        user['password'] = generate_password_hash(data['new_password'])
        
        logger.info(f"Password reset for user: {user['email']}")
        
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
    
    # Check if user exists
    if user_uuid not in users_db:
        return jsonify({'detail': 'User not found'}), 404
    
    target_user = users_db[user_uuid]
    current_user = users_db[request.user_uuid]
    
    # Check permissions
    if request.user_uuid != user_uuid and current_user.get('role') != 'Admin':
        return jsonify({'detail': 'Cannot view this user\'s profile'}), 403
    
    if request.method == 'GET':
        # Return user data (filter sensitive fields for non-admins)
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
        
        # Add admin fields if user is admin
        if current_user.get('role') == 'Admin':
            user_data['admin_type'] = target_user.get('admin_type')
            user_data['dev_specialization'] = target_user.get('dev_specialization')
        
        return jsonify(user_data), 200
    
    elif request.method in ['PATCH', 'PUT']:
        data = request.json
        
        # Editable fields
        editable_fields = ['username', 'first_name', 'last_name']
        
        # Admins can edit more
        if current_user.get('role') == 'Admin':
            editable_fields.extend(['email', 'role', 'admin_type', 'dev_specialization'])
        
        # Update fields
        for field in editable_fields:
            if field in data:
                if field == 'role' and data['role'] not in ['Student', 'Admin']:
                    continue
                if field == 'admin_type' and data.get('admin_type') not in [None, 'Manager', 'Developer']:
                    continue
                if field == 'dev_specialization' and data.get('dev_specialization') not in [None, 'Frontend', 'Backend', 'Security']:
                    continue
                
                target_user[field] = data[field]
        
        logger.info(f"User info updated: {target_user['email']}")
        
        return jsonify({'detail': 'User updated successfully'}), 200

# Initialize sample data for testing
def init_sample_data():
    """Initialize sample data for testing"""
    if not users_db:
        # Create a backend developer admin
        backend_dev_uuid = str(uuid.uuid4())
        users_db[backend_dev_uuid] = {
            'uuid': backend_dev_uuid,
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
        
        # Create a regular user
        user_uuid = str(uuid.uuid4())
        users_db[user_uuid] = {
            'uuid': user_uuid,
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
        
        logger.info("✅ Sample data initialized!")
        logger.info("   Backend Developer: backend@uptorps.com / Admin123!@#")
        logger.info("   Regular User: student@example.com / Student123!@#")

if __name__ == '__main__':
    init_sample_data()
    logger.info("\n" + "="*50)
    logger.info("🚀 Uptorps API Server Starting with FREE Email!")
    logger.info("📍 Base URL: http://localhost:5000")
    logger.info("📧 Email From: onboarding@resend.dev (FREE - No domain needed!)")
    logger.info("💯 100% FREE - No payments, no DNS, no verification!")
    logger.info("="*50 + "\n")
    app.run(debug=True, port=5000)
else:
    # When running on Render
    logger.info("🚀 Uptorps API Server started in production mode with FREE email")
    logger.info("📧 Email From: onboarding@resend.dev (FREE test domain)")