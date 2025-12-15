import time
import bcrypt
import re
from fastapi import FastAPI, Request, Depends, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from dependencies import require_roles, get_current_user
from database import engine, SessionLocal, Base
from models import User
from auth import create_access_token
from fastapi import HTTPException
import pyotp
app = FastAPI()
EXPIRES_SECONDS=60

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def check_password_requirements(password):
    if re.search(r"[a-z]", password) is not None and re.search(r"[A-Z]", password) is not None and re.search(r"[0-9]", password) is not None and re.search(r"\W", password) is not None:
        return True
    return False


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/signup")
async def signup(req: Request, db: Session = Depends(get_db)):
    data = await req.json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    otp = data.get("otp")
    totp_secret = data.get("totp_secret")
    print("Received totp_secret:", totp_secret)
    print("Received OTP:", otp)

    if not username or not password or not email:
        return {"success": False, "message": "Missing fields."}
    if not is_valid_email(email):
        return {"success": False, "message": "Email is not valid."}
    if db.query(User).filter(User.username == username).first():
        return {"success": False, "message": "Username already exists."}
    if db.query(User).filter(User.email == email).first():
        return {"success": False, "message": "Email already exists."}
    if len(password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters."}
    if not check_password_requirements(password):
        return {"success": False, "message": "Password must contain an uppercase, lowercase letter, digit and special character."}


    if not otp:
        totp_secret = pyotp.random_base32()
        totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="Secure OTP")
        return {
            "success": True,
            "otp_required": True,
            "otp_uri": totp_uri,
            "totp_secret": totp_secret,
            "message": "Scan the QR code from otp_uri with your authenticator app, then enter the OTP."
        }
    else:
        if not totp_secret:
            print("no totp_secret")
            return {"success": False, "message": "Missing TOTP secret for verification."}
        totp = pyotp.TOTP(totp_secret)
        if not totp.verify(otp,valid_window=10):
            print("Received totp_secret repr:", repr(totp_secret))
            print("Received OTP repr:", repr(otp))
            print("Server time:",time.time())
            print("TOTP token for now",totp.now())
            print("verification failed")
            return {"success": False, "message": "Invalid OTP,please try again."}

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        user = User(username=username, email=email,password_hash=password_hash, totp_secret=totp_secret,role="USER")
        print(user)
        db.add(user)
        db.commit()
        db.refresh(user)
        return {"success": True, "message": "User registered successfully."}

@app.post("/login")
async def login(req: Request, response: Response,db: Session = Depends(get_db)):
    data = await req.json()
    username = data.get("username")
    password = data.get("password")
    otp = data.get("otp")
    if not username or not password:
        return {"success": False, "message": "Username and password required."}

    user = db.query(User).filter(User.username == username).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return {"success": False, "message": "Incorrect credentials."}

    if not otp:
        return {"success": False, "message": "OTP required for login."}
    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(otp,valid_window=10):
        return {"success": False, "message": "Invalid OTP."}

    token = create_access_token({"sub":username, "role": user.role}, expires_seconds=EXPIRES_SECONDS);
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=EXPIRES_SECONDS,
        path="/"
    )
    return {"success":True, "message": "Login successful.", "expires_in":EXPIRES_SECONDS}

@app.get("/protected")
def protected(payload=Depends(get_current_user)):
    return {
        "message": f"Hello {payload['sub']}!",
        "role": payload["role"]
    }

@app.get("/me")
def get_me(payload=Depends(get_current_user)):
    return {
        "username": payload["sub"],
        "role": payload["role"]
    }

@app.post("/admin/set-role")
def set_user_role(
    username: str,
    new_role: str,
    payload=Depends(require_roles("ADMIN")),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if new_role not in ["USER", "MODERATOR", "ADMIN"]:
        raise HTTPException(status_code=400, detail="Invalid role")

    user.role = new_role
    db.commit()

    return {
        "success": True,
        "message": f"Role of {username} updated to {new_role}"
    }

@app.get("/admin")
def admin_only(payload=Depends(require_roles("ADMIN"))):
    return {"message": "Welcome admin"}

@app.get("/moderation")
def moderation(payload=Depends(require_roles("ADMIN", "MODERATOR"))):
    return {"message": "Moderator access granted"}

@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie(
        key="access_token",
        path="/"
    )
    return {"success": True, "message": "Logged out"}

