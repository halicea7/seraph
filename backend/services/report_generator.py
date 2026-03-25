"""
Report generator — produces Markdown and HTML reports from scan findings.
"""

from datetime import datetime
from typing import Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader


_SEVERITY_RISK = {
    "critical": "Critical risk: immediate exploitation possible. Could result in full system compromise, data breach, or complete loss of service integrity and confidentiality.",
    "high": "High risk: exploitable under common conditions without requiring special privileges. An attacker could use this to gain unauthorized access or exfiltrate data.",
    "medium": "Medium risk: exploitable under specific conditions or as part of a larger attack chain. Combined with other findings, this could lead to a security incident.",
    "low": "Low risk: minimal direct impact but represents a deviation from security best practices. May contribute to a larger attack chain if left unaddressed.",
    "info": "Informational: no direct security risk identified. Noted for awareness and completeness of the assessment.",
}


def generate_report(
    project_name: str,
    report_type: str,  # "audit" or "pentest"
    targets: list[dict],
    scans: list[dict],
    findings: list[dict],
    generated_by: str = "Seraph",
    auditor: str = "Seraph (Automated)",
) -> dict:
    """
    Generate a report dict with markdown and HTML content.
    Returns: {"markdown": str, "html": str, "title": str}
    """
    templates_dir = Path(__file__).parent.parent / "templates" / "reports"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=False,
    )

    # Compute severity counts
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info").lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Risk rating
    if severity_counts["critical"] > 0:
        risk_rating = "CRITICAL"
    elif severity_counts["high"] > 0:
        risk_rating = "HIGH"
    elif severity_counts["medium"] > 0:
        risk_rating = "MEDIUM"
    elif severity_counts["low"] > 0:
        risk_rating = "LOW"
    else:
        risk_rating = "INFORMATIONAL"

    # Derive audit period from scan timestamps
    scan_starts = [s["completed_at"] for s in scans if s.get("completed_at")]
    audit_start = min(scan_starts) if scan_starts else None
    audit_end = max(scan_starts) if scan_starts else None

    # Sort findings by severity so critical comes first
    _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_sorted = sorted(findings, key=lambda f: _order.get(f.get("severity", "info"), 5))

    context = {
        "project_name": project_name,
        "report_type": report_type.title(),
        "targets": targets,
        "scans": scans,
        "findings": findings_sorted,
        "severity_counts": severity_counts,
        "risk_rating": risk_rating,
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "generated_by": generated_by,
        "auditor": auditor,
        "audit_start": audit_start,
        "audit_end": audit_end,
        "total_findings": len(findings),
        "severity_risk": _SEVERITY_RISK,
    }

    template_name = "audit_report.md.j2" if report_type == "audit" else "pentest_report.md.j2"
    tmpl = env.get_template(template_name)
    markdown_content = tmpl.render(**context)
    html_content = _markdown_to_html(markdown_content, project_name, risk_rating)

    return {
        "title": f"{project_name} — {report_type.title()} Report",
        "markdown": markdown_content,
        "html": html_content,
        "risk_rating": risk_rating,
        "severity_counts": severity_counts,
    }


def _markdown_to_html(markdown: str, title: str, risk_rating: str) -> str:
    """Convert markdown to a styled HTML report."""
    import re

    html_body = markdown

    # Headers
    html_body = re.sub(r'^#### (.+)$', r'<h4>\1</h4>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html_body, flags=re.MULTILINE)

    # Bold and italic
    html_body = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_body)
    html_body = re.sub(r'\*(.+?)\*', r'<em>\1</em>', html_body)

    # Code blocks
    html_body = re.sub(r'```[\w]*\n(.*?)```', r'<pre><code>\1</code></pre>', html_body, flags=re.DOTALL)
    html_body = re.sub(r'`(.+?)`', r'<code>\1</code>', html_body)

    # Horizontal rules
    html_body = re.sub(r'^---+$', r'<hr>', html_body, flags=re.MULTILINE)

    # Tables (basic)
    def convert_table(m):
        lines = m.group(0).strip().split('\n')
        if len(lines) < 2:
            return m.group(0)
        header = lines[0]
        rows = lines[2:]  # skip separator line
        cols = [c.strip() for c in header.split('|') if c.strip()]
        thead = '<tr>' + ''.join(f'<th>{c}</th>' for c in cols) + '</tr>'
        tbody = ''
        for row in rows:
            cells = [c.strip() for c in row.split('|') if c.strip()]
            tbody += '<tr>' + ''.join(f'<td>{c}</td>' for c in cells) + '</tr>'
        return f'<table>\n<thead>{thead}</thead>\n<tbody>{tbody}</tbody>\n</table>'

    html_body = re.sub(r'(\|.+\|\n)+', convert_table, html_body)

    # Unordered lists
    def convert_ul(m):
        items = re.findall(r'^[-*] (.+)$', m.group(0), re.MULTILINE)
        li_items = ''.join(f'<li>{item}</li>' for item in items)
        return f'<ul>{li_items}</ul>'
    html_body = re.sub(r'(^[-*] .+\n?)+', convert_ul, html_body, flags=re.MULTILINE)

    # Paragraphs (wrap standalone lines)
    lines = html_body.split('\n')
    output_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('<'):
            output_lines.append(f'<p>{stripped}</p>')
        else:
            output_lines.append(line)
    html_body = '\n'.join(output_lines)

    risk_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#f59e0b",
        "LOW": "#22c55e",
        "INFORMATIONAL": "#3b82f6",
    }.get(risk_rating, "#3b82f6")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0f1419; color: #e2e8f0; line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  .report-header {{ background: #1a1f2e; border: 1px solid #2d3748; border-radius: 12px; padding: 2rem; margin-bottom: 2rem; }}
  .report-header h1 {{ font-size: 1.8rem; color: #f1f5f9; margin-bottom: 0.5rem; }}
  .risk-badge {{ display: inline-block; padding: 0.3rem 1rem; border-radius: 999px; font-weight: 700; font-size: 0.85rem; color: #0f1419; background: {risk_color}; margin-top: 0.75rem; }}
  h1 {{ font-size: 1.5rem; color: #f1f5f9; margin: 1.5rem 0 0.75rem; }}
  h2 {{ font-size: 1.25rem; color: #94a3b8; border-bottom: 1px solid #2d3748; padding-bottom: 0.5rem; margin: 1.5rem 0 1rem; }}
  h3 {{ font-size: 1rem; color: #cbd5e1; margin: 1rem 0 0.5rem; }}
  h4 {{ font-size: 0.9rem; color: #94a3b8; margin: 0.75rem 0 0.25rem; }}
  p {{ margin: 0.5rem 0; color: #cbd5e1; }}
  ul {{ margin: 0.5rem 0 0.5rem 1.5rem; color: #cbd5e1; }}
  li {{ margin: 0.25rem 0; }}
  table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.875rem; }}
  th {{ background: #252d3d; color: #94a3b8; padding: 0.6rem 0.75rem; text-align: left; border: 1px solid #2d3748; }}
  td {{ padding: 0.6rem 0.75rem; border: 1px solid #2d3748; color: #cbd5e1; vertical-align: top; }}
  tr:nth-child(even) td {{ background: #1a1f2e; }}
  code {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; background: #252d3d; padding: 0.1rem 0.35rem; border-radius: 4px; color: #a5f3fc; }}
  pre {{ background: #0f1419; border: 1px solid #2d3748; border-radius: 8px; padding: 1rem; overflow-x: auto; margin: 1rem 0; }}
  pre code {{ background: none; padding: 0; color: #e2e8f0; }}
  hr {{ border: none; border-top: 1px solid #2d3748; margin: 1.5rem 0; }}
  strong {{ color: #f1f5f9; }}
  .severity-critical {{ color: #ef4444; font-weight: 600; }}
  .severity-high {{ color: #f97316; font-weight: 600; }}
  .severity-medium {{ color: #f59e0b; font-weight: 600; }}
  .severity-low {{ color: #22c55e; font-weight: 600; }}
  .severity-info {{ color: #3b82f6; font-weight: 600; }}
</style>
</head>
<body>
<div class="container">
<div class="report-header">
  <h1>{title}</h1>
  <div class="risk-badge">{risk_rating} RISK</div>
</div>
{html_body}
</div>
</body>
</html>"""
