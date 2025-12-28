"""
main.py
-------
Main FastAPI application.

This file defines:
- Application configuration (CORS, startup)
- Authentication routes (signup, login, logout)
- Protected routes
- Role-based access control endpoints

Optimization notes:
- Permissions are included as a snapshot in the JWT at login.
- /me returns permissions from the JWT (no DB hit).
- /me/permissions is kept for MANUAL refresh / admin UI only — DO NOT POLL IT.
"""

import re
from datetime import datetime, timedelta, timezone

import bcrypt
import pyotp
from fastapi import FastAPI, Request, Depends, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from auth import create_access_token
from database import engine, Base, get_db
from dependencies import get_current_user, require_roles, has_resource_access
from models import User, ROLE_ADMIN, ROLE_MODERATOR, ROLE_USER, ResourcePermission

# -------------------------------------------------
# Application setup
# -------------------------------------------------

app = FastAPI()

# JWT lifetime (seconds) - hard upper bound.
# NOTE: actual token lifetime may be shorter (<= earliest permission expiry).
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

def utcnow() -> datetime:
    """Timezone-aware UTC 'now'."""
    return datetime.now(timezone.utc)


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

    Optimization:
    - Embed a *permission snapshot* inside the JWT at login.
    - Token lifetime is capped by:
        - EXPIRES_SECONDS, and
        - earliest permission expiration (so token never outlives granted access)
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

    # ----- Permission snapshot for JWT -----
    now = utcnow()

    active_permissions = (
        db.query(ResourcePermission)
        .filter(
            ResourcePermission.username == user.username,
            ResourcePermission.expires_at > now,
        )
        .all()
    )

    permission_claims = [
        {
            "resource": p.resource,
            "expires_at": (
                p.expires_at.replace(tzinfo=timezone.utc).isoformat()
                if p.expires_at is not None
                else None
            ),
        }
        for p in active_permissions
    ]

    # Token should not live longer than the earliest permission expiration.
    earliest_exp = min(
        [
            (
                p.expires_at.replace(tzinfo=timezone.utc)
                if p.expires_at.tzinfo is None
                else p.expires_at
            )
            for p in active_permissions
            if p.expires_at is not None
        ],
        default=now + timedelta(seconds=EXPIRES_SECONDS),
    )

    # Compute token lifetime in seconds, ensure >= 1
    token_expires_seconds = min(
        EXPIRES_SECONDS,
        max(1, int((earliest_exp - now).total_seconds())),
    )

    # Create JWT and set cookie
    token = create_access_token(
        {
            "sub": user.username,
            "role": user.role,
            "permissions": permission_claims,
        },
        expires_seconds=token_expires_seconds,
    )

    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=token_expires_seconds,
        path="/",
    )

    return {"success": True, "expires_in": token_expires_seconds}


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
    """
    Return current authenticated user's identity + permission snapshot.

    NOTE:
    - permissions come from JWT (fast, no DB hit)
    - server-side enforcement still happens on protected endpoints
    """
    return {
        "username": payload["sub"],
        "role": payload["role"],
        "permissions": payload.get("permissions", []),
    }


@app.get("/me/permissions")
def get_my_permissions(
    payload=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    ⚠️ DO NOT POLL THIS ENDPOINT.
    Use only for manual refresh / admin UI.
    """
    now = utcnow()

    permissions = (
        db.query(ResourcePermission)
        .filter(
            ResourcePermission.username == payload["sub"],
            ResourcePermission.expires_at > now,
        )
        .all()
    )

    return {
        "permissions": [
            {
                "resource": p.resource,
                "expires_at": p.expires_at.replace(tzinfo=timezone.utc).isoformat(),
            }
            for p in permissions
        ]
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


@app.get("/moderation/reports")
def view_moderation_reports(
    payload=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    View moderation reports.

    Normally restricted to MODERATOR and ADMIN,
    but USERs may access it if they have a valid
    temporary permission.
    """
    if not has_resource_access(
        payload=payload,
        resource="moderation_reports",
        db=db,
        allowed_roles=("ADMIN", "MODERATOR"),
    ):
        raise HTTPException(
            status_code=403,
            detail="You do not have access to this resource",
        )

    # Simulated protected content
    return {
        "resource": "moderation_reports",
        "data": [
            "Report #1: Spam",
            "Report #2: Abuse",
            "Report #3: Policy violation",
        ],
    }


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

    return {
        "success": True,
        "message": f"User {username} role updated to {new_role} successfully",
    }


@app.post("/admin/grant-access")
def grant_resource_access(
    data: dict,
    payload=Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db),
):
    """
    ADMIN-only endpoint to grant or extend temporary access to a resource.
    """
    username = data.get("username")
    resource = data.get("resource")
    duration_seconds = data.get("duration_seconds")

    if not username or not resource or not duration_seconds:
        raise HTTPException(
            status_code=400,
            detail="username, resource and duration_seconds are required",
        )

    # Ensure target user exists
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    expires_at = utcnow() + timedelta(seconds=int(duration_seconds))

    # Check if permission already exists
    existing_permission = (
        db.query(ResourcePermission)
        .filter(
            ResourcePermission.username == username,
            ResourcePermission.resource == resource,
        )
        .first()
    )

    if existing_permission:
        # Extend existing permission
        existing_permission.expires_at = expires_at
        existing_permission.granted_by = payload["sub"]
    else:
        # Create new permission
        permission = ResourcePermission(
            username=username,
            resource=resource,
            expires_at=expires_at,
            granted_by=payload["sub"],
        )
        db.add(permission)

    db.commit()

    return {
        "success": True,
        "message": f"Access to '{resource}' granted to {username} until {expires_at.replace(tzinfo=timezone.utc).isoformat()}",
    }


@app.get("/case-files")
def view_case_files(
    payload=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not has_resource_access(
        payload,
        resource="case_files",
        db=db,
        allowed_roles=("ADMIN", "MODERATOR"),
    ):
        raise HTTPException(status_code=403)

    return {
        "data": [
            "Case File A",
            "Case File B",
            "Case File C",
        ]
    }


@app.get("/admin/temp-panel")
def temp_admin_panel(
    payload=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not has_resource_access(
        payload,
        resource="admin_dashboard",
        db=db,
        allowed_roles=(),
    ):
        raise HTTPException(status_code=403)

    return {
        "data": {
            "system_status": "OK",
            "active_users": 42,
            "alerts": 0,
        }
    }


@app.post("/admin/revoke-access")
def revoke_resource_access(
    data: dict,
    payload=Depends(require_roles(ROLE_ADMIN)),
    db: Session = Depends(get_db),
):
    """
    ADMIN-only endpoint to revoke a resource permission immediately.
    """
    username = data.get("username")
    resource = data.get("resource")

    if not username or not resource:
        raise HTTPException(
            status_code=400,
            detail="username and resource are required",
        )

    permission = (
        db.query(ResourcePermission)
        .filter(
            ResourcePermission.username == username,
            ResourcePermission.resource == resource,
        )
        .first()
    )

    if not permission:
        raise HTTPException(status_code=404, detail="Permission not found")

    db.delete(permission)
    db.commit()

    return {
        "success": True,
        "message": f"Access to '{resource}' revoked from {username}",
    }
