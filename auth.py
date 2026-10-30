from imports import (
    Blueprint, request, jsonify,
    generate_password_hash, check_password_hash,
    create_access_token, User, db
)

from extensions import db, jwt
import time
from services.rate_limiter import (
    is_rate_limited, record_failed_attempt, clear_attempts, DBLoginAttempts
)

login_attempts = DBLoginAttempts()


def get_client_ip():
    # Only trust request.remote_addr to prevent X-Forwarded-For spoofing attacks.
    return request.remote_addr or '127.0.0.1'


auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password are required"}), 400

    if not isinstance(data['username'], str) or len(data['username']) > 80:
        return jsonify({"error": "Username must be a string not exceeding 80 characters"}), 400

    if not isinstance(data['password'], str) or len(data['password']) > 72:
        return jsonify({"error": "Password must be a string not exceeding 72 characters"}), 400

    username = data.get('username', '')
    password = data.get('password', '')

    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    import re
    if not isinstance(username, str) or len(username) < 3 or len(username) > 80:
        return jsonify({"error": "Username must be between 3 and 80 characters."}), 400

    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return jsonify({"error": "Username can only contain letters, numbers, dots, hyphens, and underscores."}), 400

    if len(password) < 8 or len(password) > 72:
        return jsonify({"error": "Password must be between 8 and 72 characters."}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400
        
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "User created successfully"}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """Authenticate and generate JWT."""
    ip = get_client_ip()

    if is_rate_limited(ip):
        return jsonify({"error": "Too many login attempts. Please try again later."}), 429

    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password are required"}), 400
        
    if not isinstance(data['username'], str) or not isinstance(data['password'], str) or len(data['username']) > 80 or len(data['password']) > 128:
        record_failed_attempt(ip)
        return jsonify({"error": "Invalid username or password"}), 401

    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not check_password_hash(user.password_hash, data['password']):
        record_failed_attempt(ip)
        return jsonify({"error": "Invalid username or password"}), 401
        
    clear_attempts(ip)
    # Generate token using user ID
    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token), 200
