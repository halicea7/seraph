from jinja2 import Environment, FileSystemLoader
from datetime import datetime
from pathlib import Path
import json
import re

# Validate inputs before template rendering
def _validate_target(target: str) -> str:
    """Validate hostname or IP address."""
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    hostname_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
    target = target.strip()
    if ip_pattern.match(target) or hostname_pattern.match(target):
        return target
    raise ValueError(f"Invalid target: {target}")

def _validate_port_range(ports: str) -> str:
    if not ports:
        return "1-65535"
    if re.match(r'^[\d,\-]+$', ports):
        return ports
    raise ValueError(f"Invalid port range: {ports}")

def _validate_timing(timing: str) -> str:
    match = re.search(r'T([0-5])', timing)
    if match:
        return f"-{match.group(0)}"
    return "-T3"

SCAN_TEMPLATE_MAP = {
    "network_discovery": "nmap_discovery.sh.j2",
    "vulnerability_scan": "nmap_vuln.sh.j2",
    "web_audit": "nikto_web.sh.j2",
    "host_hardening": "lynis_audit.sh.j2",
    "openscap": "openscap_check.sh.j2",
    "cloud_aws": "aws_security_check.sh.j2",
    "log_monitoring": "log_monitoring.sh.j2",
}

def generate_script(
    project_name: str,
    target: str,
    scan_categories: list[dict],  # list of {category_id, config}
) -> str:
    """Generate a combined bash audit script from multiple scan categories."""
    templates_dir = Path(__file__).parent.parent / "templates" / "scans"
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=False,
    )

    validated_target = _validate_target(target)
    now = datetime.utcnow()
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    timestamp_short = now.strftime("%Y%m%d_%H%M%S")

    parts = [
        f"#!/usr/bin/env bash",
        f"# ============================================================",
        f"# Seraph — Combined Audit Script",
        f"# Project: {project_name}",
        f"# Target:  {validated_target}",
        f"# Generated: {timestamp}",
        f"# Scan Categories: {', '.join(c['category_id'] for c in scan_categories)}",
        f"# ============================================================",
        f"",
        f"set -euo pipefail",
        f"",
    ]

    for cat in scan_categories:
        category_id = cat["category_id"]
        config = cat.get("config", {})
        template_name = SCAN_TEMPLATE_MAP.get(category_id)
        if not template_name:
            continue

        # Build template context based on category
        ctx = {
            "project_name": project_name,
            "target": validated_target,
            "timestamp": timestamp,
            "timestamp_short": timestamp_short,
        }

        if category_id == "network_discovery":
            scan_type_raw = config.get("scan_type", "SYN (-sS)")
            flag_match = re.search(r'\((-\w+)\)', scan_type_raw)
            scan_flags = flag_match.group(1) if flag_match else "-sT"
            ctx.update({
                "scan_flags": scan_flags,
                "port_range": _validate_port_range(config.get("port_range", "1-65535")),
                "timing": _validate_timing(config.get("timing", "T3 (Normal)")),
                "os_detection": config.get("os_detection", True),
                "service_detection": config.get("service_detection", True),
                "subnet_mask": re.sub(r'[^0-9]', '', str(config.get("subnet_mask", "24")))[:2] or "24",
            })

        elif category_id == "vulnerability_scan":
            scripts = config.get("script_categories", ["vuln", "safe"])
            safe_scripts = [s for s in scripts if re.match(r'^[a-z\-]+$', s)]
            ctx.update({
                "script_categories": ",".join(safe_scripts) if safe_scripts else "vuln,safe",
                "port_range": _validate_port_range(config.get("port_range", "1-65535")),
                "timing": _validate_timing(config.get("timing", "T3 (Normal)")),
            })

        elif category_id == "web_audit":
            target_url = config.get("target_url", "")
            # Validate URL — only allow http/https
            if target_url and not re.match(r'^https?://[a-zA-Z0-9\.\-_:/]+$', target_url):
                target_url = ""
            tuning_raw = config.get("nikto_tuning", ["2", "3"])
            safe_tuning = [t[0] for t in tuning_raw if t and t[0].isdigit()]
            ctx.update({
                "target_url": target_url,
                "nikto_tuning": "".join(safe_tuning),
                "check_ssl": config.get("check_ssl", True),
                "ssl_port": re.sub(r'[^0-9]', '', str(config.get("ssl_port", "443")))[:5] or "443",
            })

        elif category_id == "host_hardening":
            profile = config.get("profile", "default")
            if profile not in ("default", "developer", "server"):
                profile = "default"
            skip_raw = config.get("skip_tests", "")
            skip_tests = re.sub(r'[^a-zA-Z0-9,_\-]', '', skip_raw)
            ctx.update({
                "profile": profile,
                "auditor_name": re.sub(r'[^a-zA-Z0-9 _\-]', '', config.get("auditor_name", "Seraph Audit"))[:50],
                "skip_tests": skip_tests,
            })

        elif category_id == "openscap":
            profile = config.get("profile", "xccdf_org.ssgproject.content_profile_cis")
            safe_profiles = [
                "xccdf_org.ssgproject.content_profile_cis",
                "xccdf_org.ssgproject.content_profile_pci-dss",
                "xccdf_org.ssgproject.content_profile_stig",
            ]
            if profile not in safe_profiles:
                profile = safe_profiles[0]
            datastream = config.get("datastream", "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml")
            # Only allow absolute paths with safe chars
            if not re.match(r'^/[a-zA-Z0-9/_\.\-]+$', datastream):
                datastream = "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
            ctx.update({"profile": profile, "datastream": datastream})

        elif category_id == "cloud_aws":
            aws_profile = re.sub(r'[^a-zA-Z0-9_\-]', '', config.get("aws_profile", "default"))[:30]
            aws_region = re.sub(r'[^a-zA-Z0-9\-]', '', config.get("aws_region", "us-east-1"))[:20]
            checks = config.get("checks", ["s3_buckets", "iam_users", "cloudtrail"])
            safe_checks = [c for c in checks if c in ("s3_buckets", "iam_users", "iam_roles", "cloudtrail", "security_groups", "security_hub")]
            ctx.update({
                "aws_profile": aws_profile or "default",
                "aws_region": aws_region or "us-east-1",
                "checks": safe_checks,
            })

        elif category_id == "log_monitoring":
            ctx.update({
                "check_auditd": config.get("check_auditd", True),
                "check_syslog": config.get("check_syslog", True),
                "check_journald": config.get("check_journald", True),
            })

        tmpl = env.get_template(template_name)
        rendered = tmpl.render(**ctx)
        # Strip the shebang and set -euo from individual templates (already in header)
        lines = rendered.split('\n')
        # Remove the shebang and set -euo from individual sections since it's in the header
        filtered = []
        skip_header = True
        for line in lines:
            if skip_header and (line.startswith('#!') or line.startswith('# =====') or line.startswith('# Seraph') or line.startswith('# Project') or line.startswith('# Target') or line.startswith('# Generated') or line.startswith('# Framework') or line == '' and not filtered):
                continue
            if skip_header and line == 'set -euo pipefail':
                skip_header = False
                continue
            if skip_header and line.startswith('set -'):
                skip_header = False
                continue
            skip_header = False
            filtered.append(line)

        parts.append(f"\n# {'='*56}")
        parts.append(f"# SECTION: {category_id.upper().replace('_', ' ')}")
        parts.append(f"# {'='*56}")
        parts.append('\n'.join(filtered))

    return '\n'.join(parts)
