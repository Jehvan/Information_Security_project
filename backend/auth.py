import time
import jwt
import os
from dotenv import load_dotenv
from datetime import datetime,timedelta
load_dotenv()
SECRET_KEY = os.environ.get("SECRET_KEY")
print(f"SECRET_KEY: {SECRET_KEY}")

def create_access_token(data, expires_minutes=120):
    payload = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    payload["exp"] = int(expire.timestamp())
    print(f"Token payload before encodeing: {payload}")
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def decode_access_token(token:str):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], leeway=30)
        print(f"Decoded token: {decoded}")
        return decoded
    except jwt.ExpiredSignatureError:
        print("Token expired")
        return None
    except jwt.InvalidTokenError as e:
        print(f"Invalid token: {str(e)}")
        return None
