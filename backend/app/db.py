from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from .config import settings


def now():
    return datetime.now(timezone.utc)


def utc_datetime(value: datetime):
    """SQLite returns naive timestamps; stored and unzoned API dates use UTC."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    pass


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="UNKNOWN", index=True)
    cvss: Mapped[float | None]
    epss: Mapped[float | None]
    kev: Mapped[bool] = mapped_column(default=False, index=True)
    published: Mapped[str | None] = mapped_column(String(60), index=True)
    modified: Mapped[str | None]
    triage: Mapped[str] = mapped_column(String(50), default="new", index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Alias(Base):
    __tablename__ = "aliases"
    id: Mapped[str] = mapped_column(String(160), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)


class Advisory(Base):
    __tablename__ = "advisories"
    id: Mapped[str] = mapped_column(String(240), primary_key=True)
    vulnerability_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    source: Mapped[str] = mapped_column(String(30), index=True)
    payload: Mapped[dict] = mapped_column(JSON)


class Activity(Base):
    __tablename__ = "activity"
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    subject: Mapped[str] = mapped_column(String(240), index=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    status: Mapped[str] = mapped_column(default="never")
    checkpoint: Mapped[str | None]
    last_run: Mapped[str | None]
    error: Mapped[str | None] = mapped_column(Text)
    count: Mapped[int] = mapped_column(default=0)


class Watch(Base):
    __tablename__ = "watchlist"
    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str]
    package: Mapped[str] = mapped_column(index=True)
    version: Mapped[str | None]
    min_severity: Mapped[str] = mapped_column(String(20), default="LOW")
    alerts_enabled: Mapped[bool] = mapped_column(default=True)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    path: Mapped[str] = mapped_column(unique=True)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    kind: Mapped[str]
    status: Mapped[str] = mapped_column(default="pending", index=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stage: Mapped[str] = mapped_column(String(40), default="queued")
    indexed: Mapped[bool] = mapped_column(default=False)


def make_engine(url):
    if url.startswith("sqlite:/// "):
        raise ValueError("Invalid database URL")
    if url.startswith("sqlite:///") and ":memory:" not in url:
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30} if url.startswith("sqlite") else {}, pool_pre_ping=True)
    if url.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def configure(connection, _):
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.close()

    return engine


engine = make_engine(settings.database_url)
Session = sessionmaker(engine, expire_on_commit=False)


def get_session():
    with Session() as session:
        yield session


class AffectedPackage(Base):
    __tablename__ = "affected_packages"
    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(80), index=True)
    package: Mapped[str] = mapped_column(String(300), index=True)
    constraints: Mapped[dict] = mapped_column(JSON)


class InventoryComponent(Base):
    __tablename__ = "inventory_components"
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    ecosystem: Mapped[str] = mapped_column(String(80), index=True)
    package: Mapped[str] = mapped_column(String(300), index=True)
    version: Mapped[str] = mapped_column(String(150))
    file: Mapped[str] = mapped_column(Text, default="")
    direct: Mapped[bool | None]
    query_status: Mapped[str] = mapped_column(String(30), default="unknown")


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("project_id", "kind", "fingerprint", name="uq_finding_identity"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(10), index=True)
    vulnerability_id: Mapped[str | None] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    package: Mapped[str | None] = mapped_column(String(300))
    ecosystem: Mapped[str | None] = mapped_column(String(80))
    version: Mapped[str | None] = mapped_column(String(150))
    file: Mapped[str] = mapped_column(Text, default="")
    line: Mapped[int | None]
    rule_id: Mapped[str | None] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(20), default="UNKNOWN", index=True)
    status: Mapped[str] = mapped_column(String(50), default="new", index=True)
    evidence: Mapped[dict] = mapped_column(JSON)
    fixed_versions: Mapped[list] = mapped_column(JSON, default=list)
    owner: Mapped[str | None] = mapped_column(String(150))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    remediation_plan: Mapped[str | None] = mapped_column(Text)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class FindingObservation(Base):
    __tablename__ = "finding_observations"
    __table_args__ = (UniqueConstraint("scan_id", "finding_id", name="uq_scan_finding"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    evidence: Mapped[dict] = mapped_column(JSON)


class PlatformSetting(Base):
    __tablename__ = "platform_settings"
    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)


class SyncRun(Base):
    __tablename__ = "sync_runs"
    id: Mapped[int] = mapped_column(primary_key=True)
    source: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(30), default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None]
    new_count: Mapped[int] = mapped_column(default=0)
    updated_count: Mapped[int] = mapped_column(default=0)
    processed_count: Mapped[int] = mapped_column(default=0)
    pages: Mapped[int] = mapped_column(default=0)
    error: Mapped[str | None] = mapped_column(Text)


class NotificationDelivery(Base):
    __tablename__ = "notification_deliveries"
    id: Mapped[int] = mapped_column(primary_key=True)
    activity_id: Mapped[int] = mapped_column(ForeignKey("activity.id"), unique=True)
    channel: Mapped[str] = mapped_column(String(20), default="webhook")
    status: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(default=0)
    last_attempt: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_attempt: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(String(200))


class ProductWatch(Base):
    __tablename__ = "product_watches"
    id: Mapped[int] = mapped_column(primary_key=True)
    vendor: Mapped[str] = mapped_column(String(200))
    product: Mapped[str] = mapped_column(String(200))
    version: Mapped[str] = mapped_column(String(100))
    alerts_enabled: Mapped[bool] = mapped_column(default=True)


class AffectedProduct(Base):
    __tablename__ = "affected_products"
    id: Mapped[int] = mapped_column(primary_key=True)
    advisory_id: Mapped[str] = mapped_column(ForeignKey("advisories.id"), index=True)
    vendor: Mapped[str] = mapped_column(String(200), index=True)
    product: Mapped[str] = mapped_column(String(200), index=True)
    constraints: Mapped[dict] = mapped_column(JSON)


class FindingState(Base):
    """Immutable states for historical reporting; never reconstruct unrecorded history."""
    __tablename__ = "finding_states"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now, index=True)
    action: Mapped[str] = mapped_column(String(30))
    data: Mapped[dict] = mapped_column(JSON)


class RadarCollection(Base):
    __tablename__ = "radar_collections"
    id: Mapped[int] = mapped_column(primary_key=True)
    since: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    basis: Mapped[str] = mapped_column(String(20), default="published")
    enrich: Mapped[bool] = mapped_column(default=True)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    progress: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
