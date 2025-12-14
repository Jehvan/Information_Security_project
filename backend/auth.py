import time

import jwt
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()
SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = "HS256"

def create_access_token(data: dict, expires_seconds: int):
    payload = data.copy()
    now = int(time.time())

    payload.update({
        "iat": now,
        "exp": now + expires_seconds,
    })

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token


def decode_access_token(token: str):
    try:
        now = int(datetime.utcnow().timestamp())
        decoded = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            leeway=30
        )
        print("NOW (server):", now)
        print("EXP (token):", decoded.get("exp"))
        print("DIFF:", decoded.get("exp") - now)
        return decoded
    except jwt.ExpiredSignatureError:
        print("Token expired (server time mismatch)")
        return None

