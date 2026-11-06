from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import JSON, DateTime, ForeignKey, String, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from .config import settings


def now():
    return datetime.now(timezone.utc)


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
