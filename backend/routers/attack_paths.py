"""
Attack Path Graph — builds a Cytoscape.js-compatible graph for a project.

Nodes:
  - "attacker" (the operator)
  - one node per Target
  - one node per imported AD collection (represents its domain)

Edges:
  - c2: attacker → target (active C2 session)
  - finding: attacker → target (exploitable finding)
  - lateral: target → target (credential reuse — same credential seen on both hosts)
  - ad: attacker → AD domain (a BloodHound/SharpHound quick-win: kerberoastable
        accounts, AS-REP roastable accounts, unconstrained delegation, etc.)
        -- quick wins are domain-wide facts, not tied to any one Target row,
        so they get their own node rather than trying to force-fit them onto
        whichever Target happens to be the domain controller.

The response is shaped for direct consumption by Cytoscape.js on the frontend.
"""

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from database import ADCollection, C2Session, Credential, Finding, Scan, Target, get_db
from routers.auth import get_current_user

router = APIRouter(prefix="/attack-paths", tags=["attack_paths"])


def _build_graph(project_id: str, db: Session) -> dict:
    targets = db.query(Target).filter(Target.project_id == project_id).all()
    collections = db.query(ADCollection).filter(ADCollection.project_id == project_id).all()
    if not targets and not collections:
        return {"nodes": [], "edges": []}

    target_ids = [t.id for t in targets]

    # C2 sessions for this project's targets
    sessions = (
        db.query(C2Session)
        .filter(C2Session.project_id == project_id)
        .all()
    )
    active_target_ids = {s.target_id for s in sessions if s.status == "active"}

    # Findings — look up via scans
    scan_rows = db.query(Scan).filter(Scan.target_id.in_(target_ids)).all()
    scan_to_target = {s.id: s.target_id for s in scan_rows}
    scan_ids = [s.id for s in scan_rows]

    findings = db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).all() if scan_ids else []

    # Group findings by target_id
    target_findings: dict[str, list] = {tid: [] for tid in target_ids}
    for f in findings:
        tid = scan_to_target.get(f.scan_id)
        if tid:
            target_findings[tid].append(f)

    # Credentials — for lateral movement edges
    credentials = db.query(Credential).filter(Credential.project_id == project_id).all()
    # Map target_host → credential list
    host_creds: dict[str, list] = {}
    for c in credentials:
        if c.target_host:
            host_creds.setdefault(c.target_host, []).append(c)

    # Build hostname → target_id map for lateral movement
    host_to_target = {t.hostname_or_ip: t.id for t in targets}

    # ── Nodes ─────────────────────────────────────────────────────────────────

    nodes = [
        {
            "data": {
                "id": "attacker",
                "label": "Attacker",
                "type": "attacker",
                "compromised": False,
            }
        }
    ]

    for t in targets:
        compromised = t.id in active_target_ids
        severity_counts = {}
        for f in target_findings.get(t.id, []):
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
        nodes.append({
            "data": {
                "id": f"target-{t.id}",
                "label": t.hostname_or_ip,
                "type": "target",
                "target_type": t.target_type,
                "compromised": compromised,
                "finding_counts": severity_counts,
            }
        })

    # ── Edges ─────────────────────────────────────────────────────────────────

    edges = []
    seen_edges: set[str] = set()

    def _add_edge(source: str, target: str, label: str, etype: str, **extra) -> None:
        eid = f"{etype}-{source}-{target}"
        if eid in seen_edges:
            return
        seen_edges.add(eid)
        edges.append({
            "data": {
                "id": eid,
                "source": source,
                "target": target,
                "label": label,
                "type": etype,
                **extra,
            }
        })

    # C2 edges
    for s in sessions:
        if not s.target_id:
            continue
        _add_edge(
            "attacker",
            f"target-{s.target_id}",
            "C2 Session",
            "c2",
            session_type=s.session_type,
            status=s.status,
            # Lets the frontend render the real re-exploit command for this
            # session's actual platform/payload instead of a hardcoded
            # windows/x64/meterpreter guess (wrong for e.g. a Linux
            # php/reverse_php shell).
            platform=s.platform,
            via_payload=s.via_payload,
        )

    # Finding edges — only for critical/high findings (exploit paths worth showing)
    for tid, flist in target_findings.items():
        exploitable = [f for f in flist if f.severity in ("critical", "high")]
        if exploitable:
            _add_edge(
                "attacker",
                f"target-{tid}",
                f"{len(exploitable)} exploit(s)",
                "finding",
                count=len(exploitable),
            )

    # Lateral movement edges — credentials that appear on multiple hosts
    for host, creds in host_creds.items():
        src_tid = host_to_target.get(host)
        if not src_tid or src_tid not in active_target_ids:
            continue
        for c in creds:
            # Find other targets where the same username appears
            for other_host, other_creds in host_creds.items():
                if other_host == host:
                    continue
                dst_tid = host_to_target.get(other_host)
                if not dst_tid:
                    continue
                matches = [oc for oc in other_creds if oc.username == c.username]
                if matches:
                    _add_edge(
                        f"target-{src_tid}",
                        f"target-{dst_tid}",
                        "Credential Reuse",
                        "lateral",
                        username=c.username,
                    )
                    break  # one edge per pair is enough

    # AD quick wins — domain-wide facts from an imported BloodHound/
    # SharpHound collection (kerberoastable accounts, AS-REP roastable
    # accounts, delegation issues, ...). Each becomes its own node + edge
    # since a quick win belongs to the domain, not any single Target.
    for coll in collections:
        quick_wins = json.loads(coll.quick_wins_json or "[]")
        if not quick_wins:
            continue
        domain_node_id = f"ad-{coll.id}"
        nodes.append({
            "data": {
                "id": domain_node_id,
                "label": coll.domain or coll.name,
                "type": "ad_domain",
                "compromised": False,
            }
        })
        for win in quick_wins:
            _add_edge(
                "attacker",
                domain_node_id,
                win.get("title", win.get("kind", "AD quick win")),
                "ad",
                kind=win.get("kind", ""),
                severity=win.get("severity", "medium"),
                count=win.get("count", 0),
                command=win.get("command", ""),
            )

    return {"nodes": nodes, "edges": edges}


@router.get("/{project_id}")
def get_attack_paths(
    project_id: str,
    db: Session = Depends(get_db),
    _=Depends(get_current_user),
):
    """Return Cytoscape.js graph data for the given project."""
    from database import Project
    if not db.query(Project).filter(Project.id == project_id).first():
        raise HTTPException(404, "Project not found")
    return _build_graph(project_id, db)
