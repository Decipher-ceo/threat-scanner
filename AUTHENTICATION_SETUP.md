# Authentication Integration Guide

## Overview
The ThreatScanner project now has a complete authentication system integrated with the backend API. Users can register, login, and access protected features using JWT tokens.

## What Was Implemented

### Backend Changes

1. **User Model** (`backend/models.py`)
   - Added `User` model with username, email, password_hash, and is_admin fields
   - Password hashing using Werkzeug's security functions
   - User serialization method

2. **Authentication Utilities** (`backend/auth_utils.py`)
   - JWT token generation and validation
   - Authentication decorator for protected routes
   - Token extraction from Authorization headers

3. **API Endpoints** (`backend/app.py`)
   - `POST /api/auth/register` - User registration
   - `POST /api/auth/login` - User login
   - `GET /api/auth/me` - Get current user info (protected)
   - `POST /api/auth/logout` - Logout endpoint

4. **Database Initialization** (`backend/init_db.py`)
   - Creates database tables
   - Creates default admin user (username: `admin`, password: `admin123`)

### Frontend Changes

1. **Authentication JavaScript** (`frontend/assets/auth.js`)
   - Complete rewrite to use backend API instead of localStorage
   - JWT token storage and management
   - Automatic token validation
   - Login/signup handlers with API calls

2. **HTML Pages Updated**
   - `login.html` - Uses new API-based authentication
   - `signup.html` - Uses new API-based authentication
   - `dashboard.html` - Includes auth.js for authentication checks
   - `testing.html` - Includes auth.js for authentication checks

### Dependencies Added

- `PyJWT==2.8.0` - For JWT token handling

## Setup Instructions

### 1. Install Dependencies

```bash
cd /home/decipher/Desktop/ThreatScanner/phishing_line
pip install -r requirements.txt
```

### 2. Initialize Database

```bash
python3 -m backend.init_db
```

This will:
- Create all database tables (including the new `users` table)
- Create a default admin user:
  - Username: `admin`
  - Password: `admin123`
  - Email: `admin@threatscanner.com`

**⚠️ Important:** Change the admin password after first login!

### 3. Configure Secret Key (Optional but Recommended)

Create a `.env` file in the `backend` directory:

```bash
cd backend
echo "SECRET_KEY=your-very-secret-key-change-this-in-production" >> .env
echo "DATABASE_URL=sqlite:///phishing.db" >> .env
```

### 4. Run the Backend Server

```bash
python3 -m backend.app
# or
python3 backend/main.py  # if you have a main.py that runs the app
```

The server will run on `http://localhost:5000` (or `http://127.0.0.1:5000`)

### 5. Access the Frontend

Open `frontend/login.html` in your browser or access through the Flask server.

## API Usage

### Register a New User

```javascript
POST /api/auth/register
Content-Type: application/json

{
  "username": "newuser",
  "email": "user@example.com",
  "password": "password123"
}
```

Response:
```json
{
  "message": "User registered successfully",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "newuser",
    "email": "user@example.com",
    "is_admin": false
  }
}
```

### Login

```javascript
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin123"
}
```

Response:
```json
{
  "message": "Login successful",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@threatscanner.com",
    "is_admin": true
  }
}
```

### Get Current User (Protected)

```javascript
GET /api/auth/me
Authorization: Bearer <token>
```

### Using Token in Frontend

The frontend automatically stores the token in `localStorage` as `authToken` and includes it in API requests via the `Authorization` header.

## Security Features

1. **Password Hashing**: All passwords are hashed using Werkzeug's secure password hashing
2. **JWT Tokens**: Secure token-based authentication with expiration (24 hours)
3. **Token Validation**: Automatic token verification on protected routes
4. **Input Validation**: Email format validation, password length requirements

## Notes

- The scanning endpoints (`/scan-url`, `/scan-email`, `/scan-sms`) do NOT require authentication and remain publicly accessible
- JWT tokens expire after 24 hours
- Users are automatically redirected to login if not authenticated
- The frontend automatically includes the auth token in API requests when available

## Troubleshooting

### "Authentication required" error
- Check if the token is stored in localStorage: `localStorage.getItem('authToken')`
- Verify the token hasn't expired (tokens expire after 24 hours)
- Make sure the Authorization header is being sent: `Authorization: Bearer <token>`

### "User already exists" error
- The username or email is already registered
- Try a different username or email

### Backend connection errors
- Ensure the Flask server is running on port 5000
- Check the API_BASE_URL in `auth.js` matches your server URL
- Verify CORS is enabled (already configured in `app.py`)

## Next Steps (Optional Enhancements)

1. Add password reset functionality
2. Add email verification
3. Add user profile management
4. Add role-based access control for admin features
5. Add rate limiting for authentication endpoints
6. Add session management for better security
