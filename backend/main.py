"""
main.py
-------
Main FastAPI application.

This file defines:
- Application configuration (CORS, startup)
- Authentication routes (signup, login, logout)
- Protected routes
- Role-based access control endpoints
"""

import re

import bcrypt
import pyotp
from fastapi import FastAPI, Request, Depends, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from auth import create_access_token
from database import engine, Base, get_db
from dependencies import get_current_user, require_roles
from models import User, ROLE_ADMIN, ROLE_MODERATOR, ROLE_USER

# -------------------------------------------------
# Application setup
# -------------------------------------------------

app = FastAPI()

# JWT lifetime (seconds)
EXPIRES_SECONDS = 60

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create database tables on startup
Base.metadata.create_all(bind=engine)

# -------------------------------------------------
# Helper validation functions
# -------------------------------------------------

def is_valid_email(email: str) -> bool:
    """Validate email format."""
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def check_password_requirements(password: str) -> bool:
    """
    Enforce strong password rules:
    - lowercase
    - uppercase
    - digit
    - special character
    """
    return (
        re.search(r"[a-z]", password)
        and re.search(r"[A-Z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"\W", password)
    )

# -------------------------------------------------
# Authentication routes
# -------------------------------------------------

@app.post("/signup")
async def signup(request: Request, db: Session = Depends(get_db)):
    """
    User registration with TOTP setup.

    Flow:
    1. Validate input
    2. Generate TOTP secret if OTP not provided
    3. Verify OTP
    4. Create user
    """
    data = await request.json()

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    otp = data.get("otp")
    totp_secret = data.get("totp_secret")

    # Basic validation
    if not username or not email or not password:
        return {"success": False, "message": "Missing fields"}

    if not is_valid_email(email):
        return {"success": False, "message": "Invalid email"}

    if len(password) < 8 or not check_password_requirements(password):
        return {"success": False, "message": "Weak password"}

    # Uniqueness checks
    if db.query(User).filter(User.username == username).first():
        return {"success": False, "message": "Username already exists"}

    if db.query(User).filter(User.email == email).first():
        return {"success": False, "message": "Email already exists"}

    # Step 1: Generate TOTP secret and QR code
    if not otp:
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(
            name=username,
            issuer_name="Secure OTP"
        )
        return {
            "success": True,
            "otp_required": True,
            "otp_uri": totp_uri,
            "totp_secret": totp_secret,
        }

    # Step 2: Verify OTP
    totp = pyotp.TOTP(totp_secret)
    if not totp.verify(otp, valid_window=1):
        return {"success": False, "message": "Invalid OTP"}

    # Step 3: Create user
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    user = User(
        username=username,
        email=email,
        password_hash=password_hash,
        totp_secret=totp_secret,
        role=ROLE_USER,
    )

    db.add(user)
    db.commit()

    return {"success": True, "message": "User registered successfully"}

@app.post("/login")
async def login(request: Request, response: Response, db: Session = Depends(get_db)):
    """
    Login with username/password + OTP.
    Sets a secure HttpOnly JWT cookie.
    """
    data = await request.json()

    username = data.get("username")
    password = data.get("password")
    otp = data.get("otp")

    if not username or not password or not otp:
        return {"success": False, "message": "Missing credentials"}

    user = db.query(User).filter(User.username == username).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return {"success": False, "message": "Invalid credentials"}

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(otp, valid_window=1):
        return {"success": False, "message": "Invalid OTP"}

    # Create JWT and set cookie
    token = create_access_token(
        {"sub": user.username, "role": user.role},
        expires_seconds=EXPIRES_SECONDS,
    )

    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=EXPIRES_SECONDS,
        path="/",
    )

    return {"success": True, "expires_in": EXPIRES_SECONDS}

@app.post("/logout")
async def logout(response: Response):
    """Logout by deleting the session cookie."""
    response.delete_cookie(key="access_token", path="/")
    return {"success": True}

# -------------------------------------------------
# Protected routes
# -------------------------------------------------

@app.get("/protected")
def protected(payload=Depends(get_current_user)):
    """Accessible to any authenticated user."""
    return {
        "message": f"Hello {payload['sub']}",
        "role": payload["role"],
    }

@app.get("/me")
def get_me(payload=Depends(get_current_user)):
    """Return current authenticated user's identity."""
    return {
        "username": payload["sub"],
        "role": payload["role"],
    }

# -------------------------------------------------
# Role-based access control routes
# -------------------------------------------------

@app.get("/admin")
def admin_only(payload=Depends(require_roles(ROLE_ADMIN))):
    return {"message": "Welcome admin"}

@app.get("/moderation")
def moderation(payload=Depends(require_roles(ROLE_ADMIN, ROLE_MODERATOR))):
    return {"message": "Moderator access granted"}

@app.post("/admin/set-role")
def set_user_role(
    username: str,
    new_role: str,
    payload=Depends(require_roles(ROLE_ADMIN)),
    db: Session = Depends(get_db),
):
    """
    Admin-only endpoint to update user roles.
    """
    if new_role not in {ROLE_USER, ROLE_MODERATOR, ROLE_ADMIN}:
        raise HTTPException(status_code=400, detail="Invalid role")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = new_role
    db.commit()

    return {"success": True}
