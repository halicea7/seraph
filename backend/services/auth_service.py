"""
JWT + bcrypt auth helpers.
Secret key is read from the SERAPH_SECRET_KEY env var.
In development, a random key is generated per-process if the var is unset.
In production, always set SERAPH_SECRET_KEY to a long random string.
"""
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from jose import JWTError, jwt

_env_key = os.getenv("SERAPH_SECRET_KEY")
if _env_key:
    SECRET_KEY = _env_key
else:
    import logging
    logging.getLogger(__name__).warning(
        "SERAPH_SECRET_KEY not set — using a random key. "
        "All sessions will be invalidated on restart. "
        "Set SERAPH_SECRET_KEY in production."
    )
    SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
TOKEN_EXPIRE_HOURS = 24


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def create_token(data: dict) -> str:
    expire = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode({**data, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
