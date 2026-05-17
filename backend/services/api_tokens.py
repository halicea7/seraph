import hashlib
import secrets
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from database import ApiToken, User

_PREFIX = "srph_"
_TOKEN_BYTES = 32   # 64 hex chars after the prefix


def generate_token() -> tuple[str, str, str]:
    """Return (plaintext, sha256_hash, display_prefix)."""
    raw = secrets.token_hex(_TOKEN_BYTES)
    plaintext = _PREFIX + raw
    token_hash = _hash(plaintext)
    prefix = raw[:8]
    return plaintext, token_hash, prefix


def _hash(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


def validate_token(plaintext: str, db: Session) -> Optional[User]:
    """Look up a token by hash, update last_used_at, return the owning User or None."""
    if not plaintext.startswith(_PREFIX):
        return None
    token_hash = _hash(plaintext)
    record = db.query(ApiToken).filter(ApiToken.token_hash == token_hash).first()
    if not record:
        return None
    user = db.query(User).filter(User.id == record.user_id, User.is_active == True).first()
    if not user:
        return None
    record.last_used_at = datetime.utcnow()
    db.commit()
    return user


def create_token_record(user_id: str, name: str, token_hash: str, prefix: str, db: Session) -> ApiToken:
    record = ApiToken(user_id=user_id, name=name, token_hash=token_hash, prefix=prefix)
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def list_tokens(user_id: str, db: Session) -> list[ApiToken]:
    return (
        db.query(ApiToken)
        .filter(ApiToken.user_id == user_id)
        .order_by(ApiToken.created_at.desc())
        .all()
    )


def revoke_token(token_id: str, user_id: str, db: Session) -> bool:
    record = db.query(ApiToken).filter(
        ApiToken.id == token_id,
        ApiToken.user_id == user_id,
    ).first()
    if not record:
        return False
    db.delete(record)
    db.commit()
    return True
