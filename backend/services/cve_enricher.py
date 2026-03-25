import json
import re
import urllib.error
import urllib.request
from typing import Optional

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def extract_cve_ids(text: str) -> list[str]:
    if not text:
        return []
    # Preserve first-occurrence order, dedupe
    seen: dict[str, None] = {}
    for m in CVE_RE.finditer(text):
        seen[m.group(0).upper()] = None
    return list(seen)


def fetch_cve(cve_id: str) -> Optional[dict]:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id.upper()}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Seraph/0.1"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except Exception:
        return None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None

    cve = vulns[0].get("cve", {})

    # CVSS: prefer v3.1 → v3.0 → v2
    metrics = cve.get("metrics", {})
    cvss_score: Optional[str] = None
    cvss_vector: Optional[str] = None
    severity_label: Optional[str] = None
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        bucket = metrics.get(version)
        if bucket:
            m = bucket[0]
            cvss_data = m.get("cvssData", {})
            cvss_score = str(cvss_data.get("baseScore", "")) or None
            cvss_vector = cvss_data.get("vectorString") or None
            severity_label = cvss_data.get("baseSeverity") or m.get("baseSeverity") or None
            break

    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )
    references = [r["url"] for r in cve.get("references", [])[:5]]

    return {
        "cve_id": cve_id.upper(),
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity_label": severity_label,
        "description": description,
        "references": references,
    }
