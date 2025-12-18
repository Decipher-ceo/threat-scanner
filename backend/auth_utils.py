"""
Authentication utilities for JWT token generation and validation
"""
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from .config import SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRATION_HOURS

def generate_token(user_id, username, email, is_admin=False):
    """Generate a JWT token for a user"""
    payload = {
        "user_id": user_id,
        "username": username,
        "email": email,
        "is_admin": is_admin,
        "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

def verify_token(token):
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_current_user_from_token():
    """Extract current user from Authorization header token"""
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None
    
    try:
        # Extract token from "Bearer <token>" format
        token = auth_header.split(" ")[1] if " " in auth_header else auth_header
        payload = verify_token(token)
        return payload
    except Exception:
        return None

def require_auth(f):
    """Decorator to require authentication for a route - BYPASS MODE"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # BYPASS: Always inject a mock user
        mock_user = {
            "user_id": 1,
            "username": "Developer",
            "email": "dev@local.host",
            "is_admin": True
        }
        kwargs["current_user"] = mock_user
        return f(*args, **kwargs)
    return decorated_function
