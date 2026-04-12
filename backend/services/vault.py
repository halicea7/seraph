"""
AES-256-GCM encryption for sensitive database fields (Credential.secret, Credential.notes).

Key derivation
--------------
  Production : SHA-256 of the SERAPH_SECRET_KEY environment variable.
  Development: fixed insecure dev key (stable across restarts so data survives).
               Set SERAPH_SECRET_KEY before running in any shared or production env.

Storage format
--------------
  Encrypted  : "enc:<base64(12-byte nonce || ciphertext || 16-byte GCM tag)>"
  Legacy / empty: stored as-is (no prefix). decrypt() returns them unchanged so
                  existing plaintext rows are readable without a migration step.
                  They will be re-encrypted the next time the row is written.
"""
import base64
import hashlib
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Text
from sqlalchemy.types import TypeDecorator

logger = logging.getLogger(__name__)

_PREFIX = "enc:"

_env_key = os.getenv("SERAPH_SECRET_KEY", "")
if _env_key:
    _AES_KEY: bytes = hashlib.sha256(_env_key.encode()).digest()
else:
    logger.warning(
        "SERAPH_SECRET_KEY not set — credential vault is using the insecure "
        "development key. Any credentials stored will NOT be protected. "
        "Set SERAPH_SECRET_KEY to a long random string before production use."
    )
    # Fixed dev key: stable across restarts so dev data doesn't corrupt, but
    # offers zero real security — that's the point; it forces the operator to set
    # the env var for anything real.
    _AES_KEY = hashlib.sha256(b"seraph-dev-vault-key-not-for-production").digest()


def encrypt(plaintext: str) -> str:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Returns a prefixed base64 string or the original value if it is empty /
    already encrypted.  Idempotent: calling encrypt on an already-encrypted
    value is a no-op.
    """
    if not plaintext:
        return plaintext
    if plaintext.startswith(_PREFIX):
        return plaintext  # already encrypted — don't double-encrypt
    nonce = os.urandom(12)  # 96-bit nonce; unique per encryption
    aesgcm = AESGCM(_AES_KEY)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return _PREFIX + base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt(value: str) -> str:
    """
    Decrypt a value previously produced by :func:`encrypt`.

    If *value* has no ``enc:`` prefix it is treated as legacy plaintext and
    returned unchanged (backward-compatible migration path).  Decryption errors
    log a warning and return an empty string rather than propagating an
    exception and crashing a page load.
    """
    if not value or not value.startswith(_PREFIX):
        return value  # legacy plaintext row — pass through unchanged
    try:
        raw = base64.b64decode(value[len(_PREFIX):])
        nonce, ct = raw[:12], raw[12:]
        aesgcm = AESGCM(_AES_KEY)
        return aesgcm.decrypt(nonce, ct, None).decode("utf-8")
    except Exception:
        logger.error(
            "vault.decrypt: decryption failed (wrong key or corrupted data). "
            "Returning empty string to avoid leaking partial data."
        )
        return ""


class EncryptedText(TypeDecorator):
    """
    SQLAlchemy column type that transparently encrypts values on write and
    decrypts them on read.  Drop-in replacement for ``Text`` / ``String``.

    Usage in a model::

        from services.vault import EncryptedText

        class Credential(Base):
            secret = Column(EncryptedText, default="")
            notes  = Column(EncryptedText, default="")
    """

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Encrypt before INSERT / UPDATE."""
        if value is None:
            return value
        return encrypt(str(value))

    def process_result_value(self, value, dialect):
        """Decrypt after SELECT."""
        if value is None:
            return value
        return decrypt(value)
