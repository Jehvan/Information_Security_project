"""
dependencies.py
---------------
Authentication and authorization dependencies for FastAPI.

This file contains:
- get_current_user: validates the JWT session stored in a cookie
- require_roles: enforces role-based access control (RBAC)
- has_resource_access: hybrid RBAC + temporary resource access (JWT-first, DB-authoritative)

Security notes:
- JWT permissions are treated as a *snapshot hint*, never as authority
- Database remains the source of truth for enforcement
- All time comparisons are timezone-aware (UTC)
"""

from datetime import datetime, timezone
from fastapi import Request, HTTPException, status, Depends
from sqlalchemy.orm import Session

from auth import decode_access_token
from models import ResourcePermission


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def utcnow() -> datetime:
    """Timezone-aware UTC now."""
    return datetime.now(timezone.utc)


# -------------------------------------------------
# Authentication
# -------------------------------------------------

def get_current_user(request: Request) -> dict:
    """
    Authentication dependency.

    Extracts the JWT access token from the HttpOnly cookie,
    validates it, and returns the decoded payload.

    Raises:
        401 Unauthorized if the user is not authenticated

    Returns:
        Decoded JWT payload
        Example:
        {
            "sub": "jovan",
            "role": "USER",
            "permissions": [...]
        }
    """
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    return payload


# -------------------------------------------------
# Role-Based Access Control (RBAC)
# -------------------------------------------------

def require_roles(*roles: str):
    """
    Authorization dependency (RBAC).

    Ensures the authenticated user has one of the required roles.

    Usage:
        @app.get("/admin")
        def admin_route(payload=Depends(require_roles("ADMIN")))
    """

    def role_checker(payload: dict = Depends(get_current_user)) -> dict:
        user_role = payload.get("role")

        if user_role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient privileges",
            )

        return payload

    return role_checker


# -------------------------------------------------
# Resource-Based Access Control (ABAC)
# -------------------------------------------------

def has_resource_access(
    payload: dict,
    resource: str,
    db: Session,
    allowed_roles: tuple = ("ADMIN", "MODERATOR"),
) -> bool:
    """
    Check whether the current user has access to a specific resource.

    Access is granted if:
    1. The user's role is in allowed_roles (RBAC)
    OR
    2. The user has a valid, unexpired temporary permission (ABAC)

    Optimization:
    - JWT permission snapshot is checked FIRST (cheap)
    - Database is checked SECOND (authoritative)
    """

    username = payload.get("sub")
    role = payload.get("role")
    now = utcnow()

    # -------------------------------------------------
    # 1️⃣ Role-based access (fast path)
    # -------------------------------------------------
    if role in allowed_roles:
        return True

    # -------------------------------------------------
    # 2️⃣ JWT permission snapshot (hint, not authority)
    # -------------------------------------------------
    jwt_permissions = payload.get("permissions", [])

    for perm in jwt_permissions:
        if perm.get("resource") != resource:
            continue

        expires_at_raw = perm.get("expires_at")
        if not expires_at_raw:
            continue

        try:
            expires_at = datetime.fromisoformat(expires_at_raw)
        except ValueError:
            continue

        # Normalize timezone (defensive)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at > now:
            # JWT says access *might* be valid
            break
    else:
        # JWT does not even claim access → skip DB
        return False

    # -------------------------------------------------
    # 3️⃣ Database verification (source of truth)
    # -------------------------------------------------
    permission = (
        db.query(ResourcePermission)
        .filter(
            ResourcePermission.username == username,
            ResourcePermission.resource == resource,
            ResourcePermission.expires_at > now,
        )
        .first()
    )

    return permission is not None
