import json
import os
import shutil

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import CrackingJob, get_db

router = APIRouter(prefix="/cracking", tags=["cracking"])

HASHCAT_TYPES = [
    {"id": "0",    "label": "MD5"},
    {"id": "100",  "label": "SHA-1"},
    {"id": "1400", "label": "SHA-256"},
    {"id": "1700", "label": "SHA-512"},
    {"id": "1000", "label": "NTLM"},
    {"id": "3200", "label": "bcrypt"},
    {"id": "500",  "label": "md5crypt (Unix $1$)"},
    {"id": "1800", "label": "sha512crypt (Unix $6$)"},
    {"id": "2500", "label": "WPA-EAPOL-PBKDF2"},
    {"id": "13100","label": "Kerberos TGS (etype 23)"},
]

JOHN_FORMATS = [
    {"id": "auto",         "label": "Auto-detect"},
    {"id": "nt",           "label": "NTLM"},
    {"id": "md5",          "label": "MD5"},
    {"id": "sha1",         "label": "SHA-1"},
    {"id": "bcrypt",       "label": "bcrypt"},
    {"id": "sha256crypt",  "label": "sha256crypt"},
    {"id": "sha512crypt",  "label": "sha512crypt"},
    {"id": "krb5tgs",      "label": "Kerberos TGS"},
]

COMMON_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt",
]


@router.get("/tools")
def get_tools():
    return {
        "hashcat": {"available": shutil.which("hashcat") is not None},
        "john":    {"available": shutil.which("john") is not None},
        "hash_types":   HASHCAT_TYPES,
        "john_formats": JOHN_FORMATS,
        "wordlists": [p for p in COMMON_WORDLISTS if os.path.exists(p)],
    }


class CrackingRunRequest(BaseModel):
    project_id: str = ""
    tool: str                          # hashcat | john
    hashes: list[str]
    hash_type: str = "0"               # hashcat -m  /  john --format
    attack_mode: str = "0"             # hashcat -a (ignored for john)
    wordlist: str = ""
    mask: str = ""                     # hashcat -a 3 mask e.g. ?d?d?d?d?d?d?d?d
    credential_ids: list[str] = []


@router.post("/run")
def run_cracking(req: CrackingRunRequest, db: Session = Depends(get_db)):
    if req.tool not in ("hashcat", "john"):
        raise HTTPException(400, "Tool must be 'hashcat' or 'john'")
    if not req.hashes:
        raise HTTPException(400, "No hashes provided")

    # Build the command template (HASH_FILE and OUT_FILE substituted by WS endpoint)
    if req.tool == "hashcat":
        attack_arg = req.mask if req.attack_mode == "3" else "WORD_FILE"
        command = (
            f"hashcat -m {req.hash_type} -a {req.attack_mode} HASH_FILE {attack_arg}"
            " --outfile OUT_FILE --outfile-format 2 --status --status-timer 10 --force"
        )
    else:
        fmt_flag = f"--format={req.hash_type} " if req.hash_type != "auto" else ""
        command = f"john {fmt_flag}--wordlist=WORD_FILE HASH_FILE"

    job = CrackingJob(
        project_id=req.project_id or None,
        tool=req.tool,
        status="pending",
        config_json=json.dumps({
            "tool": req.tool,
            "command": command,
            "hashes": req.hashes,
            "wordlist": req.wordlist,
            "attack_mode": req.attack_mode,
            "credential_ids": req.credential_ids,
            "project_id": req.project_id,
        }),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return {"job_id": job.id}
