import bcrypt
import re
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from auth import decode_access_token
from database import engine, SessionLocal, Base
from models import User
from auth import create_access_token
from fastapi import HTTPException, Header
app = FastAPI()
Base.metadata.create_all(bind=engine)

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/signup")
async def signup(req: Request, db: Session = Depends(get_db)):
    data = await req.json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")
    if not username or not password:
        return {"success": False, "message": "Missing fields."}
    if db.query(User).filter(User.username == username).first():
        return {"success": False, "message": "Username already exists."}
    if db.query(User).filter(User.email == email).first():
        return {"success": False, "message": "Email already exists."}
    if len(password) < 8:
        return {"success": False, "message": "Password must be at least 8 characters."}
    if not check_password_requirements(password):
        return {"success": False, "message": "Password must contain an uppercase, lowercase letter, digit and special character."}

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    user = User(username=username, email=email,password_hash=password_hash)
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"success": True, "message": "User registered successfully."}

@app.post("/login")
async def login(req: Request,db: Session = Depends(get_db)):
    data = await req.json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return {"success": False, "message": "Username and password required."}

    user = db.query(User).filter(User.username == username).first()
    if not user or not bcrypt.checkpw(password.encode(), user.password_hash.encode()):
        return {"success": False, "message": "Incorrect credentials."}
    token = create_access_token({"sub":username})
    return {"success":True, "token":token, "message": "Login successful."}

@app.get("/protected")
async def protected_route(authorization: str = Header(None)):
    print(f"Authorization header: {authorization}")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split(" ")[1]
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"message": f"Hello, {payload['sub']}!"}