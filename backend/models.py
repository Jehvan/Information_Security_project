"""
models.py
---------
Database models (ORM mappings).

This file defines the structure of database tables
used by the application.
"""

from sqlalchemy import Column, Integer, String
from database import Base


# ---- Role constants (used for RBAC) ----
ROLE_USER = "USER"
ROLE_MODERATOR = "MODERATOR"
ROLE_ADMIN = "ADMIN"


class User(Base):
    """
    User model.

    Represents an authenticated user of the system.
    Each user:
    - has login credentials
    - uses TOTP-based 2FA
    - has exactly one role for RBAC
    """

    __tablename__ = "users"

    # Primary key (internal identifier)
    id = Column(Integer, primary_key=True, index=True)

    # Unique username used for login
    username = Column(String, unique=True, index=True, nullable=False)

    # Unique email address
    email = Column(String, unique=True, index=True, nullable=False)

    # Hashed password (bcrypt hash)
    # Never store plaintext passwords
    password_hash = Column(String, nullable=False)

    # TOTP secret (Base32), used for OTP verification
    # Shared between server and authenticator app
    totp_secret = Column(String, nullable=False)

    # Role used for Role-Based Access Control (RBAC)
    # Possible values: USER, MODERATOR, ADMIN
    role = Column(String, nullable=False, default=ROLE_USER)
