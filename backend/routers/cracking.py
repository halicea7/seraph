import json
import os
import pathlib
import shutil

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from database import Credential, CrackingJob, CrackingServer, get_db

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

# Local wordlists directory (user-writable, no root needed)
_WORDLIST_DIR = str(pathlib.Path(__file__).resolve().parents[2] / "wordlists")

COMMON_WORDLISTS = [
    f"{_WORDLIST_DIR}/rockyou.txt",
    f"{_WORDLIST_DIR}/rockyou.txt.gz",
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fasttrack.txt",
    "/usr/share/john/password.lst",
    f"{_WORDLIST_DIR}/top-1000.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt",
]

# Downloadable wordlist bundles — wget to local dir, no root required
WORDLIST_BUNDLES = [
    {
        "id": "rockyou",
        "label": "rockyou.txt",
        "description": "14M passwords from the 2009 RockYou breach. Best all-around list (~134 MB).",
        "dest": f"{_WORDLIST_DIR}/rockyou.txt",
        "commands": [
            f"mkdir -p {_WORDLIST_DIR}",
            f"wget -q --show-progress -O {_WORDLIST_DIR}/rockyou.txt.gz "
            "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
            # The above URL serves the plain text file despite the .gz extension in the save name
            # Rename to .txt if it downloaded as plaintext
            f"file {_WORDLIST_DIR}/rockyou.txt.gz | grep -q gzip "
            f"&& gunzip -f {_WORDLIST_DIR}/rockyou.txt.gz "
            f"|| mv {_WORDLIST_DIR}/rockyou.txt.gz {_WORDLIST_DIR}/rockyou.txt",
        ],
    },
    {
        "id": "top1000",
        "label": "Top 1000 passwords",
        "description": "Lightweight 1 KB list — cracks weak passwords in seconds.",
        "dest": f"{_WORDLIST_DIR}/top-1000.txt",
        "commands": [
            f"mkdir -p {_WORDLIST_DIR}",
            f"wget -q --show-progress -O {_WORDLIST_DIR}/top-1000.txt "
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
        ],
    },
    {
        "id": "fasttrack",
        "label": "fasttrack.txt",
        "description": "~200 passwords focused on corporate/default creds. Fast.",
        "dest": f"{_WORDLIST_DIR}/fasttrack.txt",
        "commands": [
            f"mkdir -p {_WORDLIST_DIR}",
            f"wget -q --show-progress -O {_WORDLIST_DIR}/fasttrack.txt "
            "https://raw.githubusercontent.com/trustedsec/social-engineer-toolkit/master/src/fasttrack/wordlist.txt",
        ],
    },
]


@router.get("/wordlists/available")
def list_wordlist_bundles():
    return [
        {**b, "installed": os.path.exists(b["dest"]), "commands": None}
        for b in WORDLIST_BUNDLES
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
    server_id: str = ""                # CrackingServer.id — empty means run locally
    remote_wordlist: str = ""          # wordlist path on the remote server


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
        server_id=req.server_id or None,
        config_json=json.dumps({
            "tool": req.tool,
            "command": command,
            "hashes": req.hashes,
            "wordlist": req.wordlist,
            "attack_mode": req.attack_mode,
            "credential_ids": req.credential_ids,
            "project_id": req.project_id,
            "server_id": req.server_id,
            "remote_wordlist": req.remote_wordlist,
            "hash_type": req.hash_type,
        }),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return {"job_id": job.id}


# ── Cracking Server CRUD ────────────────────────────────────────────────────

class CrackingServerCreate(BaseModel):
    name: str
    host: str
    port: int = 22
    ssh_user: str
    key_credential_id: Optional[str] = None
    remote_workdir: str = "/tmp/seraph_crack"


@router.get("/servers")
def list_cracking_servers(db: Session = Depends(get_db)):
    servers = db.query(CrackingServer).order_by(CrackingServer.created_at).all()
    return [
        {
            "id": s.id,
            "name": s.name,
            "host": s.host,
            "port": s.port,
            "ssh_user": s.ssh_user,
            "key_credential_id": s.key_credential_id,
            "remote_workdir": s.remote_workdir,
            "created_at": s.created_at,
        }
        for s in servers
    ]


@router.post("/servers")
def create_cracking_server(req: CrackingServerCreate, db: Session = Depends(get_db)):
    if req.key_credential_id:
        cred = db.query(Credential).filter(Credential.id == req.key_credential_id).first()
        if not cred:
            raise HTTPException(404, "Credential not found")
    server = CrackingServer(
        name=req.name,
        host=req.host,
        port=req.port,
        ssh_user=req.ssh_user,
        key_credential_id=req.key_credential_id or None,
        remote_workdir=req.remote_workdir,
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    return {"id": server.id, "name": server.name}


@router.delete("/servers/{server_id}")
def delete_cracking_server(server_id: str, db: Session = Depends(get_db)):
    server = db.query(CrackingServer).filter(CrackingServer.id == server_id).first()
    if not server:
        raise HTTPException(404, "Server not found")
    db.delete(server)
    db.commit()
    return {"ok": True}
