import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

from config import settings
from services.vault import EncryptedText

_connect_args = {}
if settings.database_url.startswith("sqlite"):
    _connect_args["check_same_thread"] = False

engine = create_engine(
    settings.database_url,
    connect_args=_connect_args,
    pool_pre_ping=True,
)

if settings.database_url.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, connection_record):
        """WAL lets readers and the single writer coexist instead of erroring
        out after 5s; a much longer busy_timeout absorbs real contention
        instead of silently dropping the write; foreign_keys=ON activates
        every ondelete= already declared on the models below (previously
        inert — SQLite has them off by default per-connection)."""
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    scope_json  = Column(Text, nullable=True)   # {"include": ["10.0.0.0/8"], "exclude": []}
    scratchpad  = Column(Text, default="")

    targets = relationship(
        "Target", back_populates="project", cascade="all, delete-orphan"
    )


class Target(Base):
    __tablename__ = "targets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False, index=True)
    hostname_or_ip = Column(String, nullable=False)
    target_type = Column(
        Enum(
            "linux_host",
            "windows_host",
            "web_app",
            "cloud_aws",
            "cloud_azure",
            "cloud_gcp",
            "network",
            "api_endpoint",
            name="target_type_enum",
        ),
        nullable=False,
    )
    ports = Column(String, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    project = relationship("Project", back_populates="targets")
    scans = relationship(
        "Scan", back_populates="target", cascade="all, delete-orphan"
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String, ForeignKey("targets.id"), nullable=False, index=True)
    scan_type = Column(String, nullable=False)
    module = Column(
        Enum("audit", "pentest", name="module_enum"),
        nullable=False,
    )
    status = Column(
        Enum("pending", "running", "completed", "failed", name="status_enum"),
        nullable=False,
        default="pending",
        index=True,
    )
    config_json = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    raw_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    # Nessus lifecycle tracking (populated for scan_type "nessus_job")
    nessus_scan_id = Column(Integer, nullable=True)      # the Nessus-side scan id
    nessus_status = Column(String, nullable=True)        # last polled Nessus status (running/completed/paused/…)
    nessus_progress = Column(Integer, nullable=True)     # 0–100 progress for the UI
    nessus_export_json = Column(Text, nullable=True)     # in-flight export {format, file_id, state, report_id}

    # Provenance: what exactly ran, who ran it, and under what scope — see
    # routers/ws.py:websocket_execute. {"operator": username|null,
    # "scope_snapshot": project.scope_json at run time (parsed) | null,
    # "category_ids": [...], "script_sha256": hex}
    provenance_json = Column(Text, nullable=True)

    target = relationship("Target", back_populates="scans")
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    severity = Column(
        Enum(
            "critical",
            "high",
            "medium",
            "low",
            "info",
            name="severity_enum",
        ),
        nullable=False,
    )
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    control_id = Column(String, nullable=True)
    framework = Column(String, nullable=True)
    remediation = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    cve_id = Column(String, nullable=True)
    cvss_score = Column(String, nullable=True)
    status = Column(String, default="open", index=True)   # open | in-review | remediated | accepted | false_positive
    fp_reason = Column(Text, nullable=True)   # reason for false positive suppression
    tags = Column(String, default="")         # comma-separated
    exploit_chain_json = Column(Text, nullable=True)   # JSON: [{session_id, technique, timestamp, notes}]
    fingerprint = Column(String, nullable=True)   # cve_id|control_id|normalized_title — identity within one scan, used to upsert on rescan without wiping triage

    scan = relationship("Scan", back_populates="findings")


class ScanProfile(Base):
    __tablename__ = "scan_profiles"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    description = Column(String, default="")
    scan_categories = Column(String, nullable=False)  # JSON array of {category_id, config}
    created_at = Column(DateTime, default=datetime.utcnow)
    # Scheduling
    schedule = Column(String, nullable=True)               # cron expression e.g. "0 2 * * *"
    scheduled_project_id = Column(String, nullable=True)
    scheduled_target_id = Column(String, nullable=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)


class C2Session(Base):
    __tablename__ = "c2_sessions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String, ForeignKey("targets.id", ondelete="CASCADE"), nullable=True, index=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    msf_session_id = Column(String, nullable=True, index=True)   # MSF's session ID (e.g. "1")
    session_type = Column(String, default="meterpreter")  # meterpreter, shell, ssh
    platform = Column(String, default="")             # linux, windows, etc.
    arch = Column(String, default="")
    remote_host = Column(String, default="")
    remote_port = Column(String, default="")
    tunnel_peer = Column(String, default="")
    via_exploit = Column(String, default="")
    via_payload = Column(String, default="")
    status = Column(String, default="active", index=True)         # active, inactive, lost
    notes = Column(String, default="")
    established_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    checklist_json = Column(Text, nullable=True)      # JSON array of checklist items
    pivot_routes_json = Column(Text, nullable=True)   # JSON array of active pivot routes
    sysinfo_json = Column(Text, nullable=True)         # Structured: {hostname, os, arch, username, domain, is_admin, local_time}
    finding_id = Column(String, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)  # Finding that was exploited to get this session
    # relationships
    loot = relationship("LootEntry", back_populates="session", cascade="all, delete-orphan")
    tasks = relationship("C2Task", back_populates="session", cascade="all, delete-orphan")


class LootEntry(Base):
    __tablename__ = "loot_entries"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("c2_sessions.id", ondelete="CASCADE"), nullable=False)
    loot_type = Column(String, default="credential")  # credential, hash, file, key, secret, system_info
    title = Column(String, nullable=False)
    content = Column(String, default="")
    source_path = Column(String, default="")
    captured_at = Column(DateTime, default=datetime.utcnow)
    session = relationship("C2Session", back_populates="loot")


class C2Task(Base):
    __tablename__ = "c2_tasks"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, ForeignKey("c2_sessions.id", ondelete="CASCADE"), nullable=False)
    command = Column(String, nullable=False)
    output = Column(String, default="")
    status = Column(String, default="pending")  # pending, running, done, error
    executed_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    session = relationship("C2Session", back_populates="tasks")


class CrackingJob(Base):
    __tablename__ = "cracking_jobs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    tool = Column(String, nullable=False)       # hashcat | john
    status = Column(String, default="pending")  # pending, running, completed, failed
    config_json = Column(Text, nullable=True)
    raw_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    server_id = Column(String, nullable=True)   # CrackingServer.id if remote job


class CrackingServer(Base):
    __tablename__ = "cracking_servers"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, default=22)
    ssh_user = Column(String, nullable=False)
    key_credential_id = Column(String, ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True)
    remote_workdir = Column(String, default="/tmp/seraph_crack")
    created_at = Column(DateTime, default=datetime.utcnow)


class C2Node(Base):
    __tablename__ = "c2_nodes"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    c2_type = Column(String, default="msf")         # msf | sliver
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False)
    password = Column(EncryptedText, default="")
    ssl = Column(Boolean, default=False)
    status = Column(String, default="unknown")       # unknown | connected | unreachable | pending
    last_checked = Column(DateTime, nullable=True)
    source = Column(String, default="manual")        # manual | ec2
    cloud_instance_id = Column(String, nullable=True)
    notes = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class CloudC2Instance(Base):
    __tablename__ = "cloud_c2_instances"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    provider = Column(String, default="aws")
    instance_id = Column(String, nullable=True)      # AWS: i-0abc123def456
    region = Column(String, nullable=False)
    public_ip = Column(String, nullable=True)
    status = Column(String, default="pending")       # pending|launching|running|configuring|ready|stopped|terminated|error
    c2_type = Column(String, default="msf")          # msf | sliver
    ami_id = Column(String, nullable=True)
    instance_type = Column(String, default="t3.medium")
    key_name = Column(String, nullable=True)
    sg_id = Column(String, nullable=True)
    ssh_key_credential_id = Column(String, ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True)
    node_id = Column(String, nullable=True)          # C2Node.id after provisioning
    provision_log = Column(Text, default="")
    error_msg = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SherlockJob(Base):
    __tablename__ = "sherlock_jobs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    username = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, completed, failed
    command = Column(String, nullable=True)
    raw_output = Column(Text, nullable=True)
    results_json = Column(Text, nullable=True)  # JSON array of {site, url}
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class Credential(Base):
    __tablename__ = "credentials"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    username = Column(String, default="")
    secret = Column(EncryptedText, default="")       # AES-256-GCM encrypted at rest
    cred_type = Column(String, default="password")   # password, hash, key, token, other
    source = Column(String, default="manual")         # manual, c2_loot, osint, brute_force
    target_host = Column(String, default="")
    notes = Column(EncryptedText, default="")         # AES-256-GCM encrypted at rest
    created_at = Column(DateTime, default=datetime.utcnow)


class FindingNote(Base):
    __tablename__ = "finding_notes"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    finding_id = Column(String, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class AppSetting(Base):
    __tablename__ = "app_settings"
    key = Column(String, primary_key=True)
    value = Column(Text, default="")


class Playbook(Base):
    __tablename__ = "playbooks"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    steps_json = Column(Text, nullable=False)   # JSON array of step configs
    mitre_techniques = Column(Text, default="[]")  # JSON array of T-IDs
    is_builtin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    runs = relationship("PlaybookRun", back_populates="playbook", cascade="all, delete-orphan")


class PlaybookRun(Base):
    __tablename__ = "playbook_runs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    playbook_id = Column(String, ForeignKey("playbooks.id"), nullable=False)
    project_id = Column(String, nullable=False)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    mode = Column(String, default="auto")       # auto | step_through
    status = Column(String, default="pending")  # pending | running | paused | completed | failed
    current_step = Column(String, default="0")
    results_json = Column(Text, default="{}")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    playbook = relationship("Playbook", back_populates="runs")


class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="analyst")   # admin | analyst
    is_active = Column(Boolean, default=True)
    full_name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class VulnerabilityRecord(Base):
    __tablename__ = "vulnerability_records"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, default="")
    severity = Column(String, default="medium")   # critical/high/medium/low/info
    status = Column(String, default="open")        # open/in_progress/mitigated/accepted/false_positive
    cvss_score = Column(String, nullable=True)
    cve_id = Column(String, nullable=True)
    affected_asset = Column(String, default="")
    remediation_notes = Column(Text, default="")
    ai_remediation = Column(Text, nullable=True)
    finding_id = Column(String, nullable=True)     # optional link to Finding
    tags = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String, nullable=False)
    body = Column(Text, default="")
    type = Column(String, default="info")   # info | warning | critical
    read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    scan_id = Column(String, nullable=True)   # optional deep-link to a scan


class Listener(Base):
    __tablename__ = "listeners"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)   # scheduled | threshold | healthcheck
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    target_id = Column(String, ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    config_json = Column(Text, default="{}")
    status = Column(String, default="stopped")  # running | paused | stopped
    last_triggered = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    events = relationship("ListenerEvent", back_populates="listener", cascade="all, delete-orphan")


class ListenerEvent(Base):
    __tablename__ = "listener_events"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    listener_id = Column(String, ForeignKey("listeners.id", ondelete="CASCADE"), nullable=False)
    fired_at = Column(DateTime, default=datetime.utcnow)
    outcome = Column(String, default="triggered")  # triggered | skipped | error
    detail = Column(Text, default="")
    listener = relationship("Listener", back_populates="events")


class Agent(Base):
    __tablename__ = "agents"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    target_id = Column(String, ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    token = Column(String, unique=True, nullable=False)
    short_code = Column(String, unique=True, nullable=True)  # short install URL key
    hostname = Column(String, nullable=True)
    platform = Column(String, nullable=True)
    status = Column(String, default="offline")   # online | offline
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    jobs = relationship("AgentJob", back_populates="agent", cascade="all, delete-orphan")


class AgentJob(Base):
    __tablename__ = "agent_jobs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    agent_id = Column(String, ForeignKey("agents.id", ondelete="CASCADE"))
    scan_id = Column(String, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    categories = Column(String, nullable=True)   # comma-separated category ids
    script = Column(Text, nullable=False)
    status = Column(String, default="pending")   # pending | running | completed | failed
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    output = Column(Text, nullable=True)
    exit_code = Column(Integer, nullable=True)
    agent = relationship("Agent", back_populates="jobs")


class WebhookConfig(Base):
    __tablename__ = "webhook_configs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False)
    url = Column(String, nullable=False)
    events = Column(String, default="critical,warning")  # comma-separated: critical,warning,info
    active = Column(Boolean, default=True)
    secret = Column(String, nullable=True)   # HMAC-SHA256 signing secret; None = unsigned
    created_at = Column(DateTime, default=datetime.utcnow)
    deliveries = relationship("WebhookDelivery", back_populates="webhook", cascade="all, delete-orphan")


class WebhookDelivery(Base):
    """Delivery attempt log for each webhook firing."""
    __tablename__ = "webhook_deliveries"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    webhook_id = Column(String, ForeignKey("webhook_configs.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String, nullable=False)
    title = Column(String, nullable=False)
    status_code = Column(Integer, nullable=True)   # HTTP response code, None on network failure
    attempt = Column(Integer, default=1)           # 1 / 2 / 3
    success = Column(Boolean, default=False)
    error = Column(String, nullable=True)          # error message on failure
    fired_at = Column(DateTime, default=datetime.utcnow)
    webhook = relationship("WebhookConfig", back_populates="deliveries")


class FPSuppressionRule(Base):
    """Project-level false-positive suppression rules applied at parse time."""
    __tablename__ = "fp_suppression_rules"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    tool = Column(String, nullable=True)           # None = match any tool
    title_contains = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class WatchedService(Base):
    __tablename__ = "watched_services"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    target_id = Column(String, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    service_term = Column(String, nullable=False)   # e.g. "Apache httpd 2.4.52"
    last_checked = Column(DateTime, nullable=True)
    known_cves = Column(Text, default="[]")         # JSON array of CVE IDs already seen
    created_at = Column(DateTime, default=datetime.utcnow)


class PasskeyCredential(Base):
    __tablename__ = "passkey_credentials"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    credential_id = Column(String, unique=True, nullable=False)   # base64url-encoded bytes
    public_key = Column(Text, nullable=False)                      # base64url-encoded COSE key
    sign_count = Column(Integer, default=0)
    name = Column(String, default="Passkey")                       # user-supplied label
    created_at = Column(DateTime, default=datetime.utcnow)


class RevokedToken(Base):
    """Tracks invalidated JWTs so logout is enforced server-side."""
    __tablename__ = "revoked_tokens"
    jti = Column(String, primary_key=True)          # JWT ID claim
    revoked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)    # used for periodic cleanup


class ApiToken(Base):
    """Long-lived API tokens for non-browser clients (e.g. Chronos)."""
    __tablename__ = "api_tokens"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    name = Column(String, nullable=False)            # user-supplied label e.g. "Chronos — Alex"
    token_hash = Column(String, unique=True, nullable=False)   # SHA-256 of plaintext
    prefix = Column(String, nullable=False)          # first 8 chars after "srph_" for display
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)


class HardeningReport(Base):
    __tablename__ = "hardening_reports"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    profile = Column(String, nullable=False)       # cis_l1, cis_l2, stig
    overall_score = Column(String, default="0")
    controls_json = Column(Text, default="{}")
    scan_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ADCollection(Base):
    """An imported BloodHound/SharpHound collection for an engagement.

    Graph data is stored as JSON blobs (nodes/edges) rather than relational rows —
    mirrors how PlaybookRun.results_json stores derived graph data. project_id is a
    plain FK and is NOT in the Project cascade, so delete explicitly (see demo.py).
    """
    __tablename__ = "ad_collections"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    name = Column(String, nullable=False)
    domain = Column(String, default="")
    source = Column(String, default="sharphound")   # sharphound | bloodhound-python
    stats_json = Column(Text, default="{}")          # object counts by type
    nodes_json = Column(Text, default="[]")          # [{id,label,type,flags}]
    edges_json = Column(Text, default="[]")          # [{source,target,kind}]
    quick_wins_json = Column(Text, default="[]")     # computed attack opportunities
    imported_at = Column(DateTime, default=datetime.utcnow)


class HttpRequestItem(Base):
    """A saved HTTP request for the Request Workbench (Repeater-style collection).

    project_id is a plain FK without cascade — delete explicitly with the project.
    """
    __tablename__ = "http_requests"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    name = Column(String, default="")
    method = Column(String, default="GET")
    url = Column(String, nullable=False)
    headers_json = Column(Text, default="{}")
    body = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)


class Screenshot(Base):
    """A captured web screenshot (gowitness/eyewitness) pinned to a project/target.

    project_id is a plain FK without cascade — delete explicitly with the project.
    """
    __tablename__ = "screenshots"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
    target_id = Column(String, ForeignKey("targets.id"), nullable=True)
    url = Column(String, nullable=False)
    title = Column(String, default="")
    status_code = Column(String, nullable=True)
    image_path = Column(String, nullable=False)   # absolute path on the backend host
    finding_id = Column(String, ForeignKey("findings.id"), nullable=True)  # optional: evidence for a finding
    captured_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """Security audit log — records all mutating API calls with user + IP context."""
    __tablename__ = "audit_log"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, nullable=True)         # None for unauthenticated requests
    action = Column(String, nullable=False)          # HTTP method + path, e.g. "POST /api/v1/projects"
    resource_type = Column(String, nullable=True)    # e.g. "project", "scan", "c2_session"
    resource_id = Column(String, nullable=True)
    detail = Column(Text, nullable=True)             # optional extra context (body digest, etc.)
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Job(Base):
    """Durable background job queue — lets work triggered by an HTTP
    request (e.g. auto-probe on target creation) survive an API-process
    restart, by handing it to the worker process (worker.py) via a row
    here instead of an in-process asyncio.create_task."""
    __tablename__ = "jobs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    job_type = Column(String, nullable=False)
    payload_json = Column(Text, nullable=False)
    status = Column(String, nullable=False, default="pending", index=True)  # pending|running|completed|failed
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    """Bring the database's schema to Alembic's "head" revision.

    Every real deployment so far was built by `Base.metadata.create_all()`
    (plus the old hand-rolled `_migrate()` ALTER-TABLE list) — nothing has
    ever actually run `alembic upgrade head`. Alembic's one revision is
    autogenerated from these same models, so a pre-existing database's
    schema already matches it exactly; such a database just needs to be
    marked as being at head (`stamp`), not have its tables recreated
    (`upgrade`, which issues `CREATE TABLE` and would fail on tables that
    already exist). A brand-new database has no tables at all yet, so it
    takes the normal `upgrade` path, which creates everything.
    """
    import os
    from alembic.config import Config
    from alembic import command
    from sqlalchemy import inspect

    backend_dir = os.path.dirname(os.path.abspath(__file__))
    cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))

    existing_tables = set(inspect(engine).get_table_names())
    if existing_tables and "alembic_version" not in existing_tables:
        command.stamp(cfg, "head")
    else:
        command.upgrade(cfg, "head")
