"""
dependencies.py
---------------
Authentication and authorization dependencies for FastAPI.

This file contains:
- get_current_user: validates the JWT session stored in a cookie
- require_roles: enforces role-based access control (RBAC)
"""

from fastapi import Request, HTTPException, status, Depends

from auth import decode_access_token


def get_current_user(request: Request) -> dict:
    """
    Authentication dependency.

    Extracts the JWT access token from the HttpOnly cookie,
    validates it, and returns the decoded payload.

    Raises:
        401 Unauthorized if the user is not authenticated

    Returns:
        Decoded JWT payload (e.g. {"sub": username, "role": "ADMIN"})
    """
    # Read JWT from secure HttpOnly cookie
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    # Decode and verify the token
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    return payload


def require_roles(*roles: str):
    """
    Authorization dependency (RBAC).

    Ensures the authenticated user has one of the required roles.

    Usage:
        @app.get("/admin")
        def admin_route(payload=Depends(require_roles("ADMIN")))

    Args:
        roles: Allowed roles for this endpoint

    Raises:
        403 Forbidden if the user does not have sufficient privileges

    Returns:
        JWT payload if authorization succeeds
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
