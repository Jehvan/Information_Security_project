"""
auth.py
-------
This file contains all JWT-related logic:
- Creating access tokens
- Decoding and validating access tokens

The JWT represents the user's session and is stored
in a secure HttpOnly cookie.
"""

import os
from datetime import datetime, timedelta, timezone

import jwt
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Secret key used to sign JWTs
SECRET_KEY = os.environ.get("SECRET_KEY")

# Algorithm used for signing JWTs
ALGORITHM = "HS256"

# Fail fast if SECRET_KEY is not configured
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY is missing. Add it to your .env file.")


def create_access_token(data: dict, expires_seconds: int) -> str:
    """
    Create a signed JWT access token.

    Args:
        data: Dictionary of claims to embed in the token
              (e.g. {"sub": username, "role": "ADMIN"})
        expires_seconds: How long the token is valid (in seconds)

    Returns:
        Encoded JWT string
    """
    # Use timezone-aware UTC time to avoid clock issues
    now = datetime.now(timezone.utc)

    # Copy payload so original dict is not modified
    payload = data.copy()

    # Standard JWT claims
    payload.update(
        {
            "iat": int(now.timestamp()),  # Issued at
            "exp": int((now + timedelta(seconds=expires_seconds)).timestamp()),  # Expiration
        }
    )

    # Sign and encode the token
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def decode_access_token(token: str) -> dict | None:
    """
    Decode and validate a JWT access token.

    Args:
        token: JWT string from the HttpOnly cookie

    Returns:
        Decoded payload if valid, otherwise None
    """
    try:
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            leeway=30,  # allow small clock drift
        )
    except jwt.ExpiredSignatureError:
        # Token has expired
        return None
    except jwt.InvalidTokenError:
        # Token was tampered with or malformed
        return None
