"""Initial schema — all Seraph tables.

Revision ID: 000001
Revises:
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "000001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── projects ──────────────────────────────────────────────────────────────
    op.create_table(
        "projects",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("scope_json", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── targets ───────────────────────────────────────────────────────────────
    op.create_table(
        "targets",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("hostname_or_ip", sa.String(), nullable=False),
        sa.Column("target_type", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── scans ─────────────────────────────────────────────────────────────────
    op.create_table(
        "scans",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("scan_type", sa.String(), nullable=False),
        sa.Column("module", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("raw_output", sa.Text(), nullable=True),
        sa.Column("config_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── findings ──────────────────────────────────────────────────────────────
    op.create_table(
        "findings",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=False),
        sa.Column("severity", sa.Enum("critical", "high", "medium", "low", "info", name="severity_enum"), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("control_id", sa.String(), nullable=True),
        sa.Column("framework", sa.String(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=True),
        sa.Column("cvss_score", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("tags", sa.String(), nullable=True),
        sa.Column("exploit_chain_json", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── scan_profiles ─────────────────────────────────────────────────────────
    op.create_table(
        "scan_profiles",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("scan_categories", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("schedule", sa.String(), nullable=True),
        sa.Column("scheduled_project_id", sa.String(), nullable=True),
        sa.Column("scheduled_target_id", sa.String(), nullable=True),
        sa.Column("last_run", sa.DateTime(), nullable=True),
        sa.Column("next_run", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── c2_sessions ───────────────────────────────────────────────────────────
    op.create_table(
        "c2_sessions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=True),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("msf_session_id", sa.String(), nullable=True),
        sa.Column("session_type", sa.String(), nullable=True),
        sa.Column("platform", sa.String(), nullable=True),
        sa.Column("arch", sa.String(), nullable=True),
        sa.Column("remote_host", sa.String(), nullable=True),
        sa.Column("remote_port", sa.String(), nullable=True),
        sa.Column("tunnel_peer", sa.String(), nullable=True),
        sa.Column("via_exploit", sa.String(), nullable=True),
        sa.Column("via_payload", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("notes", sa.String(), nullable=True),
        sa.Column("established_at", sa.DateTime(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("checklist_json", sa.Text(), nullable=True),
        sa.Column("pivot_routes_json", sa.Text(), nullable=True),
        sa.Column("sysinfo_json", sa.Text(), nullable=True),
        sa.Column("finding_id", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── loot_entries ──────────────────────────────────────────────────────────
    op.create_table(
        "loot_entries",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("loot_type", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("content", sa.String(), nullable=True),
        sa.Column("source_path", sa.String(), nullable=True),
        sa.Column("captured_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["session_id"], ["c2_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── c2_tasks ──────────────────────────────────────────────────────────────
    op.create_table(
        "c2_tasks",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=False),
        sa.Column("command", sa.String(), nullable=False),
        sa.Column("output", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["session_id"], ["c2_sessions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── notifications ─────────────────────────────────────────────────────────
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("type", sa.String(), nullable=True),
        sa.Column("read", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── app_settings ──────────────────────────────────────────────────────────
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("key"),
    )

    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("full_name", sa.String(), nullable=True),
        sa.UniqueConstraint("username"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── revoked_tokens ────────────────────────────────────────────────────────
    op.create_table(
        "revoked_tokens",
        sa.Column("jti", sa.String(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("jti"),
    )

    # ── credentials ───────────────────────────────────────────────────────────
    op.create_table(
        "credentials",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("password", sa.Text(), nullable=True),
        sa.Column("hash", sa.Text(), nullable=True),
        sa.Column("cred_type", sa.String(), nullable=True),
        sa.Column("service", sa.String(), nullable=True),
        sa.Column("host", sa.String(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── vulnerability_records ─────────────────────────────────────────────────
    op.create_table(
        "vulnerability_records",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("cve_id", sa.String(), nullable=True),
        sa.Column("cvss_score", sa.String(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("affected_asset", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.Column("finding_ids", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── audit_reports ─────────────────────────────────────────────────────────
    op.create_table(
        "audit_reports",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("report_type", sa.String(), nullable=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── webhook_configs ───────────────────────────────────────────────────────
    op.create_table(
        "webhook_configs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("url", sa.String(), nullable=False),
        sa.Column("events", sa.String(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── watched_services ──────────────────────────────────────────────────────
    op.create_table(
        "watched_services",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=False),
        sa.Column("service_term", sa.String(), nullable=False),
        sa.Column("known_cves", sa.Text(), nullable=True),
        sa.Column("last_checked", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── passkey_credentials ───────────────────────────────────────────────────
    op.create_table(
        "passkey_credentials",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("credential_id", sa.Text(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── agents ────────────────────────────────────────────────────────────────
    op.create_table(
        "agents",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("token", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("platform", sa.String(), nullable=True),
        sa.Column("hostname", sa.String(), nullable=True),
        sa.Column("last_seen", sa.DateTime(), nullable=True),
        sa.Column("project_id", sa.String(), nullable=True),
        sa.Column("target_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("short_code", sa.String(), nullable=True),
        sa.UniqueConstraint("token"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── agent_jobs ────────────────────────────────────────────────────────────
    op.create_table(
        "agent_jobs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("agent_id", sa.String(), nullable=False),
        sa.Column("scan_id", sa.String(), nullable=True),
        sa.Column("categories", sa.String(), nullable=True),
        sa.Column("script", sa.Text(), nullable=True),
        sa.Column("output", sa.Text(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── listeners ─────────────────────────────────────────────────────────────
    op.create_table(
        "listeners",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=True),
        sa.Column("config_json", sa.Text(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("last_triggered", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── listener_events ───────────────────────────────────────────────────────
    op.create_table(
        "listener_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("listener_id", sa.String(), nullable=False),
        sa.Column("outcome", sa.String(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["listener_id"], ["listeners.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── playbooks ─────────────────────────────────────────────────────────────
    op.create_table(
        "playbooks",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("steps_json", sa.Text(), nullable=False),
        sa.Column("is_builtin", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── playbook_runs ─────────────────────────────────────────────────────────
    op.create_table(
        "playbook_runs",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("playbook_id", sa.String(), nullable=False),
        sa.Column("target_id", sa.String(), nullable=True),
        sa.Column("project_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("current_step", sa.Integer(), nullable=True),
        sa.Column("step_mode", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["playbook_id"], ["playbooks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── finding_notes ─────────────────────────────────────────────────────────
    op.create_table(
        "finding_notes",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("finding_id", sa.String(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── audit_log ─────────────────────────────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("resource_type", sa.String(), nullable=True),
        sa.Column("resource_id", sa.String(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("finding_notes")
    op.drop_table("playbook_runs")
    op.drop_table("playbooks")
    op.drop_table("listener_events")
    op.drop_table("listeners")
    op.drop_table("agent_jobs")
    op.drop_table("agents")
    op.drop_table("passkey_credentials")
    op.drop_table("watched_services")
    op.drop_table("webhook_configs")
    op.drop_table("audit_reports")
    op.drop_table("vulnerability_records")
    op.drop_table("credentials")
    op.drop_table("revoked_tokens")
    op.drop_table("users")
    op.drop_table("app_settings")
    op.drop_table("notifications")
    op.drop_table("c2_tasks")
    op.drop_table("loot_entries")
    op.drop_table("c2_sessions")
    op.drop_table("scan_profiles")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("targets")
    op.drop_table("projects")
    # Drop enum type (PostgreSQL only)
    try:
        sa.Enum(name="severity_enum").drop(op.get_bind(), checkfirst=True)
    except Exception:
        pass
