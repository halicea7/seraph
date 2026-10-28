"""Post-exploitation checklist — moved out of routers/c2.py so
services/scheduler.py can use the same default checklist when it creates a
C2Session from a live MSF/Sliver session, without importing a router module
(a layering violation)."""
import json
from datetime import datetime

DEFAULT_CHECKLIST = [
    {"id": "sysinfo",       "category": "recon",       "label": "System info (sysinfo / uname -a)",          "done": False, "done_at": None},
    {"id": "whoami",        "category": "recon",       "label": "Current user (getuid / whoami)",             "done": False, "done_at": None},
    {"id": "processes",     "category": "recon",       "label": "Process list (ps)",                          "done": False, "done_at": None},
    {"id": "network",       "category": "recon",       "label": "Network interfaces (ifconfig / ipconfig)",   "done": False, "done_at": None},
    {"id": "routes",        "category": "recon",       "label": "Routing table",                              "done": False, "done_at": None},
    {"id": "local_users",   "category": "recon",       "label": "Local users / passwd",                      "done": False, "done_at": None},
    {"id": "hashdump",      "category": "creds",       "label": "Dump password hashes",                      "done": False, "done_at": None},
    {"id": "kiwi",          "category": "creds",       "label": "Mimikatz / kiwi creds_all",                 "done": False, "done_at": None},
    {"id": "privesc",       "category": "escalation",  "label": "Local exploit suggester",                   "done": False, "done_at": None},
    {"id": "screenshot",    "category": "evidence",    "label": "Screenshot (meterpreter)",                   "done": False, "done_at": None},
    {"id": "persist_check", "category": "persistence", "label": "Cron / scheduled tasks check",              "done": False, "done_at": None},
    {"id": "pivot_check",   "category": "lateral",     "label": "Identify pivot opportunities",              "done": False, "done_at": None},
]


def tick_checklist(session, item_ids: list, db) -> None:
    """Mark checklist items as done if not already ticked."""
    if not session.checklist_json:
        session.checklist_json = json.dumps(DEFAULT_CHECKLIST)
    items = json.loads(session.checklist_json)
    now = datetime.utcnow().isoformat()
    changed = False
    for item in items:
        if item["id"] in item_ids and not item["done"]:
            item["done"] = True
            item["done_at"] = now
            changed = True
    if changed:
        session.checklist_json = json.dumps(items)
