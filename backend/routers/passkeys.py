"""
WebAuthn / Passkey endpoints.

Registration flow (requires existing JWT session):
  POST /passkeys/register/begin     → returns PublicKeyCredentialCreationOptions JSON
  POST /passkeys/register/complete  → verifies and stores the new credential

Authentication flow (no JWT needed):
  POST /passkeys/authenticate/begin     → returns PublicKeyCredentialRequestOptions JSON
  POST /passkeys/authenticate/complete  → verifies assertion, returns JWT

Management (requires JWT):
  GET    /passkeys/           → list registered passkeys for current user
  DELETE /passkeys/{pk_id}    → remove a passkey
"""

import json
import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from config import settings
from database import PasskeyCredential, User, get_db
from routers.auth import get_current_user
from services.auth_service import create_token

import webauthn
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
    RegistrationCredential,
    AuthenticationCredential,
)

router = APIRouter(prefix="/passkeys", tags=["passkeys"])

# In-memory challenge store: { challenge_key: challenge_bytes }
# challenge_key is a random hex token returned to the client so it can be echoed
# back during the "complete" step.
_challenges: dict[str, bytes] = {}


def _store_challenge(key: str, challenge: bytes) -> None:
    _challenges[key] = challenge
    # Prune old entries if the dict grows large (simple defence against leak)
    if len(_challenges) > 500:
        # Drop oldest 250
        for k in list(_challenges.keys())[:250]:
            _challenges.pop(k, None)


def _pop_challenge(key: str) -> bytes:
    ch = _challenges.pop(key, None)
    if ch is None:
        raise HTTPException(400, "Challenge expired or not found — restart the passkey flow")
    return ch


# ── Registration ──────────────────────────────────────────────────────────────

@router.post("/register/begin")
def register_begin(current_user: User = Depends(get_current_user)):
    """Generate WebAuthn registration options for the currently logged-in user."""
    options = webauthn.generate_registration_options(
        rp_id=settings.rp_id,
        rp_name=settings.app_name,
        user_id=current_user.id.encode(),
        user_name=current_user.username,
        user_display_name=current_user.full_name or current_user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    challenge_key = os.urandom(16).hex()
    _store_challenge(challenge_key, options.challenge)

    options_dict = json.loads(webauthn.options_to_json(options))
    options_dict["_challenge_key"] = challenge_key
    return options_dict


class RegisterCompleteRequest(BaseModel):
    challenge_key: str
    credential: dict
    name: Optional[str] = "Passkey"


@router.post("/register/complete", status_code=201)
def register_complete(
    req: RegisterCompleteRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify the authenticator's attestation response and save the new credential."""
    challenge = _pop_challenge(req.challenge_key)

    origins = [o.strip() for o in settings.rp_origins.split(",") if o.strip()]
    try:
        reg_credential = RegistrationCredential.parse_raw(json.dumps(req.credential))
        verified = webauthn.verify_registration_response(
            credential=reg_credential,
            expected_challenge=challenge,
            expected_rp_id=settings.rp_id,
            expected_origin=origins,
            require_user_verification=False,
        )
    except Exception as exc:
        raise HTTPException(400, f"Registration verification failed: {exc}")

    # Check for duplicate credential ID
    cred_id_b64 = bytes_to_base64url(verified.credential_id)
    if db.query(PasskeyCredential).filter(PasskeyCredential.credential_id == cred_id_b64).first():
        raise HTTPException(409, "This passkey is already registered")

    pk = PasskeyCredential(
        id=str(uuid.uuid4()),
        user_id=current_user.id,
        credential_id=cred_id_b64,
        public_key=bytes_to_base64url(verified.credential_public_key),
        sign_count=verified.sign_count,
        name=(req.name or "Passkey").strip() or "Passkey",
    )
    db.add(pk)
    db.commit()
    db.refresh(pk)
    return {"id": pk.id, "name": pk.name, "created_at": str(pk.created_at)}


# ── Authentication ────────────────────────────────────────────────────────────

class AuthBeginRequest(BaseModel):
    username: Optional[str] = None


@router.post("/authenticate/begin")
def authenticate_begin(req: AuthBeginRequest, db: Session = Depends(get_db)):
    """Generate WebAuthn authentication options.

    If `username` is provided, only that user's credentials are included in
    allowCredentials (reduces friction for non-resident-key authenticators).
    If omitted, an empty allowCredentials list is sent (works with resident keys /
    discoverable credentials like iCloud Keychain).
    """
    allow: list[PublicKeyCredentialDescriptor] = []

    if req.username:
        user = db.query(User).filter(User.username == req.username).first()
        if user:
            creds = db.query(PasskeyCredential).filter(PasskeyCredential.user_id == user.id).all()
            allow = [
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(c.credential_id))
                for c in creds
            ]

    options = webauthn.generate_authentication_options(
        rp_id=settings.rp_id,
        allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    challenge_key = os.urandom(16).hex()
    _store_challenge(challenge_key, options.challenge)

    options_dict = json.loads(webauthn.options_to_json(options))
    options_dict["_challenge_key"] = challenge_key
    return options_dict


class AuthCompleteRequest(BaseModel):
    challenge_key: str
    credential: dict


@router.post("/authenticate/complete")
def authenticate_complete(req: AuthCompleteRequest, db: Session = Depends(get_db)):
    """Verify the authenticator assertion and return a JWT if valid."""
    challenge = _pop_challenge(req.challenge_key)

    try:
        auth_credential = AuthenticationCredential.parse_raw(json.dumps(req.credential))
    except Exception as exc:
        raise HTTPException(400, f"Could not parse credential: {exc}")

    # Look up stored credential by raw ID (the browser sends it base64url-encoded)
    cred_id_b64 = bytes_to_base64url(auth_credential.raw_id)
    stored = db.query(PasskeyCredential).filter(PasskeyCredential.credential_id == cred_id_b64).first()
    if not stored:
        raise HTTPException(401, "Passkey not recognised")

    user = db.query(User).filter(User.id == stored.user_id).first()
    if not user or not user.is_active:
        raise HTTPException(401, "Account disabled or not found")

    origins = [o.strip() for o in settings.rp_origins.split(",") if o.strip()]
    try:
        verified = webauthn.verify_authentication_response(
            credential=auth_credential,
            expected_challenge=challenge,
            expected_rp_id=settings.rp_id,
            expected_origin=origins,
            credential_public_key=base64url_to_bytes(stored.public_key),
            credential_current_sign_count=stored.sign_count,
            require_user_verification=False,
        )
    except Exception as exc:
        raise HTTPException(401, f"Passkey verification failed: {exc}")

    # Update sign count to prevent replay attacks
    stored.sign_count = verified.new_sign_count
    db.commit()

    token = create_token({"sub": user.id, "role": user.role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "full_name": user.full_name or "",
            "created_at": str(user.created_at),
        },
    }


# ── Management ────────────────────────────────────────────────────────────────

@router.get("/")
def list_passkeys(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    creds = db.query(PasskeyCredential).filter(PasskeyCredential.user_id == current_user.id).all()
    return [{"id": c.id, "name": c.name, "created_at": str(c.created_at)} for c in creds]


class RenameRequest(BaseModel):
    name: str


@router.patch("/{pk_id}")
def rename_passkey(
    pk_id: str,
    req: RenameRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    pk = db.query(PasskeyCredential).filter(
        PasskeyCredential.id == pk_id,
        PasskeyCredential.user_id == current_user.id,
    ).first()
    if not pk:
        raise HTTPException(404, "Passkey not found")
    pk.name = req.name.strip() or "Passkey"
    db.commit()
    return {"id": pk.id, "name": pk.name}


@router.delete("/{pk_id}", status_code=204)
def delete_passkey(
    pk_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    pk = db.query(PasskeyCredential).filter(
        PasskeyCredential.id == pk_id,
        PasskeyCredential.user_id == current_user.id,
    ).first()
    if not pk:
        raise HTTPException(404, "Passkey not found")
    db.delete(pk)
    db.commit()
