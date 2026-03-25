from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import Finding, Scan, Target, get_db

router = APIRouter(prefix="/network", tags=["network"])

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@router.get("/graph")
def get_graph(project_id: str, db: Session = Depends(get_db)):
    targets = db.query(Target).filter(Target.project_id == project_id).all()

    nodes = [
        {
            "id": "root",
            "label": "Seraph",
            "type": "root",
            "severity": None,
            "finding_count": 0,
            "target_type": None,
        }
    ]
    edges = []

    for target in targets:
        findings = (
            db.query(Finding)
            .join(Scan)
            .filter(Scan.target_id == target.id)
            .all()
        )

        highest = None
        for f in findings:
            if highest is None or SEVERITY_RANK.get(f.severity, 0) > SEVERITY_RANK.get(highest, 0):
                highest = f.severity

        nodes.append({
            "id": target.id,
            "label": target.hostname_or_ip,
            "type": "target",
            "severity": highest,
            "finding_count": len(findings),
            "target_type": target.target_type,
        })

    # Build edges — detect subdomain parent/child relationships
    target_map = {t.id: t.hostname_or_ip for t in targets}
    linked: set[str] = set()

    for tid, host in target_map.items():
        for pid, phost in target_map.items():
            if tid != pid and host.endswith(f".{phost}"):
                edges.append({"source": pid, "target": tid})
                linked.add(tid)
                break

    for tid in target_map:
        if tid not in linked:
            edges.append({"source": "root", "target": tid})

    return {"nodes": nodes, "edges": edges}
