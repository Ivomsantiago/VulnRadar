import os
import hashlib
from datetime import datetime, timezone

os.environ["VULNRADAR_DATABASE_URL"] = "sqlite:///:memory:"
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from app.db import Base, get_session
from app.main import app
from app.config import settings
from app.config import AccessKey
from app.access import buckets, sessions

TEST_KEY = "v4-test-only-" + "a" * 29 + "b"


@pytest.fixture(autouse=True)
def isolated_osv_queries(monkeypatch):
    monkeypatch.setattr(settings, "access_keys", {"test-admin": AccessKey(digest=hashlib.sha256(TEST_KEY.encode()).hexdigest(), role="admin", expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc))})
    buckets.clear()
    sessions.clear()
    monkeypatch.setattr(settings, "osv_batch", False)
    monkeypatch.setattr(settings, "osv_queries_enabled", True)
    monkeypatch.setattr(settings, "requests_per_minute", 60000)
    monkeypatch.setattr(settings, "mutations_per_minute", 6000)


@pytest.fixture
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with sessionmaker(engine, expire_on_commit=False)() as value:
        yield value
    engine.dispose()


@pytest.fixture
def client(session):
    app.dependency_overrides[get_session] = lambda: session
    value = TestClient(app, client=("127.0.0.1", 50000))
    value.headers["Authorization"] = "Bearer " + TEST_KEY
    yield value
    value.close()
    app.dependency_overrides.clear()
