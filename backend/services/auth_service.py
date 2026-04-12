"""
JWT + bcrypt auth helpers.

SERAPH_SECRET_KEY must be set in the environment (or .env file).
The server will refuse to start if it is absent — there is no insecure fallback.

Generate a key with:
    python3 -c "import secrets; print(secrets.token_hex(32))"
"""
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from jose import JWTError, jwt

_env_key = os.getenv("SERAPH_SECRET_KEY", "")
if not _env_key:
    raise RuntimeError(
        "\n\n"
        "  SERAPH_SECRET_KEY is not set.\n"
        "  The server cannot start without a signing key — this protects all\n"
        "  user sessions and the encrypted credential vault.\n\n"
        "  Generate a key and add it to seraph/.env:\n"
        '    python3 -c "import secrets; print(secrets.token_hex(32))"\n\n'
        "  Then add:  SERAPH_SECRET_KEY=<generated-key>\n"
    )

SECRET_KEY: str = _env_key
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
    payload = {
        **data,
        "exp": expire,
        "jti": str(uuid.uuid4()),   # unique token ID — enables server-side revocation
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None


def validate_password_strength(password: str) -> Optional[str]:
    """
    Return an error message if the password fails policy, else None.

    Policy: at least 12 characters, at least one uppercase letter,
    at least one lowercase letter, at least one digit.
    """
    if len(password) < 12:
        return "Password must be at least 12 characters."
    if not any(c.isupper() for c in password):
        return "Password must contain at least one uppercase letter."
    if not any(c.islower() for c in password):
        return "Password must contain at least one lowercase letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one digit."
    return None
