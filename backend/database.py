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
    text,
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
)

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
    project_id = Column(String, ForeignKey("projects.id"), nullable=False)
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
    target_id = Column(String, ForeignKey("targets.id"), nullable=False)
    scan_type = Column(String, nullable=False)
    module = Column(
        Enum("audit", "pentest", name="module_enum"),
        nullable=False,
    )
    status = Column(
        Enum("pending", "running", "completed", "failed", name="status_enum"),
        nullable=False,
        default="pending",
    )
    config_json = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    raw_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    target = relationship("Target", back_populates="scans")
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
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
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    cve_id = Column(String, nullable=True)
    cvss_score = Column(String, nullable=True)
    status = Column(String, default="open")   # open | in-review | remediated | accepted | false_positive
    fp_reason = Column(Text, nullable=True)   # reason for false positive suppression
    tags = Column(String, default="")         # comma-separated
    exploit_chain_json = Column(Text, nullable=True)   # JSON: [{session_id, technique, timestamp, notes}]

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
    target_id = Column(String, ForeignKey("targets.id", ondelete="CASCADE"), nullable=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    msf_session_id = Column(String, nullable=True)   # MSF's session ID (e.g. "1")
    session_type = Column(String, default="meterpreter")  # meterpreter, shell, ssh
    platform = Column(String, default="")             # linux, windows, etc.
    arch = Column(String, default="")
    remote_host = Column(String, default="")
    remote_port = Column(String, default="")
    tunnel_peer = Column(String, default="")
    via_exploit = Column(String, default="")
    via_payload = Column(String, default="")
    status = Column(String, default="active")         # active, inactive, lost
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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    Base.metadata.create_all(bind=engine)
    _migrate()
    _cleanup_noise_findings()


_NIKTO_NOISE_SUBSTRINGS = [
    "No CGI Directories found",
    "Host maximum execution time",
    "SSL connect failed",
    "No web server found",
    "0 item(s) reported",
    "end of test.",
]


def _cleanup_noise_findings():
    """Remove known noisy / non-actionable findings created by older parser versions."""
    db = SessionLocal()
    try:
        for pattern in _NIKTO_NOISE_SUBSTRINGS:
            db.query(Finding).filter(Finding.title.contains(pattern)).delete(synchronize_session=False)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


def _migrate():
    """Safely add new columns to existing tables without dropping data."""
    migrations = [
        "ALTER TABLE findings ADD COLUMN cve_id VARCHAR",
        "ALTER TABLE findings ADD COLUMN cvss_score VARCHAR",
        "ALTER TABLE findings ADD COLUMN status VARCHAR DEFAULT 'open'",
        "ALTER TABLE findings ADD COLUMN tags VARCHAR DEFAULT ''",
        "ALTER TABLE scan_profiles ADD COLUMN schedule VARCHAR",
        "ALTER TABLE scan_profiles ADD COLUMN scheduled_project_id VARCHAR",
        "ALTER TABLE scan_profiles ADD COLUMN scheduled_target_id VARCHAR",
        "ALTER TABLE scan_profiles ADD COLUMN last_run DATETIME",
        "ALTER TABLE scan_profiles ADD COLUMN next_run DATETIME",
        "ALTER TABLE notifications ADD COLUMN scan_id VARCHAR",
        "ALTER TABLE users ADD COLUMN full_name VARCHAR",
        "ALTER TABLE agents ADD COLUMN short_code VARCHAR",
        "ALTER TABLE projects ADD COLUMN scope_json TEXT",
        "ALTER TABLE c2_sessions ADD COLUMN checklist_json TEXT",
        "ALTER TABLE c2_sessions ADD COLUMN pivot_routes_json TEXT",
        "ALTER TABLE c2_sessions ADD COLUMN sysinfo_json TEXT",
        "ALTER TABLE c2_sessions ADD COLUMN finding_id VARCHAR",
        "ALTER TABLE findings ADD COLUMN exploit_chain_json TEXT",
        "ALTER TABLE findings ADD COLUMN fp_reason TEXT",
        "ALTER TABLE webhook_configs ADD COLUMN secret VARCHAR",
        "ALTER TABLE projects ADD COLUMN scratchpad TEXT DEFAULT ''",
        "ALTER TABLE playbooks ADD COLUMN mitre_techniques TEXT DEFAULT '[]'",
        "ALTER TABLE cracking_jobs ADD COLUMN server_id VARCHAR",
        # webhook_deliveries, fp_suppression_rules, api_tokens, cracking_servers, c2_nodes, cloud_c2_instances created by create_all
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception:
                conn.rollback()  # Column already exists — skip
