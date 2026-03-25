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

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
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
            "network",
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
    status = Column(String, default="open")   # open | in-review | remediated | accepted
    tags = Column(String, default="")         # comma-separated

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


class Credential(Base):
    __tablename__ = "credentials"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    username = Column(String, default="")
    secret = Column(String, default="")
    cred_type = Column(String, default="password")  # password, hash, key, token, other
    source = Column(String, default="manual")        # manual, c2_loot, osint, brute_force
    target_host = Column(String, default="")
    notes = Column(Text, default="")
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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables():
    Base.metadata.create_all(bind=engine)
    _migrate()


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
    ]
    with engine.connect() as conn:
        for sql in migrations:
            try:
                conn.execute(text(sql))
                conn.commit()
            except Exception:
                conn.rollback()  # Column already exists — skip
