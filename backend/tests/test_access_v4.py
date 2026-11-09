from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select

from app import access
from app.config import AccessKey, Settings, settings
from app.db import Activity
from app.main import app

HEADERS = {"X-VulnRadar-Client": "web"}


@pytest.fixture
def keys(monkeypatch, client):
    client.headers.pop("authorization", None)
    access.sessions.clear()
    access.buckets.clear()
    values = {role: secrets.token_urlsafe(32) for role in ("viewer", "analyst", "admin")}
    monkeypatch.setattr(settings, "access_keys", {role: AccessKey(digest=hashlib.sha256(value.encode()).hexdigest(), role=role, expires_at=datetime.now(timezone.utc) + timedelta(days=1)) for role, value in values.items()})
    yield values
    access.sessions.clear()
    access.buckets.clear()


def bearer(key):
    return {**HEADERS, "Authorization": "Bearer " + key}


def test_team_fails_closed_on_missing_keys_or_insecure_origin():
    with pytest.raises(ValueError):
        Settings(access_mode="team", _env_file=None)


def test_no_identity_no_workspace_or_schema_access(client, keys):
    for path in ("/api/findings/1", "/api/projects", "/api/scans/1/export", "/api/export", "/docs", "/openapi.json"):
        response = client.get(path)
        assert response.status_code == 401, path
        assert response.headers["Cache-Control"] == "no-store" if path.startswith("/api/") else True
        assert response.headers["X-Request-ID"]
    assert client.get("/api/auth/session").json()["principal"] is None


@pytest.mark.parametrize("role,expected", [("viewer", 403), ("analyst", 403), ("admin", 201)])
def test_admin_function_cannot_be_reached_by_role_or_header_tampering(client, keys, role, expected, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "allowed_roots", [str(tmp_path)])
    response = client.post("/api/projects", json={"name": "Test workspace", "path": str(tmp_path)}, headers={**bearer(keys[role]), "X-Role": "admin"})
    assert response.status_code == expected


def test_cookie_rotates_logout_revokes_and_invalid_bearer_does_not_fall_back(client, keys):
    first = client.post("/api/auth/login", json={"access_key": keys["admin"]}, headers=HEADERS)
    assert first.status_code == 200
    cookie = client.cookies.get(access.COOKIE)
    assert "HttpOnly" in first.headers["set-cookie"] and "SameSite=strict" in first.headers["set-cookie"]
    assert client.get("/api/projects").status_code == 200
    assert client.get("/api/projects", headers=bearer("x" * 43)).status_code == 401
    client.post("/api/auth/login", json={"access_key": keys["admin"]}, headers=HEADERS)
    assert client.cookies.get(access.COOKIE) != cookie
    assert hashlib.sha256(cookie.encode()).hexdigest() not in access.sessions
    current = client.cookies.get(access.COOKIE)
    assert client.post("/api/auth/logout", headers=HEADERS).status_code == 204
    assert client.get("/api/projects", headers={"Cookie": f"{access.COOKIE}={current}"}).status_code == 401


def test_expired_and_revoked_keys_invalidate_existing_sessions(client, keys, monkeypatch):
    client.post("/api/auth/login", json={"access_key": keys["viewer"]}, headers=HEADERS)
    stored = next(iter(access.sessions.values()))
    stored.created -= settings.session_minutes * 60 + 1
    assert client.get("/api/projects").status_code == 401
    client.post("/api/auth/login", json={"access_key": keys["viewer"]}, headers=HEADERS)
    monkeypatch.setattr(settings, "access_keys", {})
    monkeypatch.setattr(settings, "access_mode", "team")
    client.base_url = "https://testserver"
    assert client.get("/api/projects").status_code == 503


def test_team_requires_tls_and_sets_secure_cookie(client, keys, monkeypatch):
    monkeypatch.setattr(settings, "access_mode", "team")
    assert client.get("/api/projects", headers=bearer(keys["viewer"])).status_code == 403
    client.base_url = "https://testserver"
    response = client.post("/api/auth/login", json={"access_key": keys["viewer"]}, headers=HEADERS)
    assert response.status_code == 200
    assert "Secure" in response.headers["set-cookie"]
    assert response.headers["Strict-Transport-Security"]


def test_role_matrix_rejects_unknown_routes_and_viewer_mutations(client, keys):
    assert client.patch("/api/preferences", json={"theme": "light"}, headers=bearer(keys["viewer"])).status_code == 403
    assert client.get("/api/settings", headers=bearer(keys["viewer"])).status_code == 403
    assert client.get("/api/findings/999", headers=bearer(keys["viewer"])).status_code == 404
    assert not access.permitted("analyst", "POST", "/api/new-admin-feature")
    assert not access.permitted("viewer", "GET", "/api/new-sensitive-feature")


def test_auth_rate_limit_and_validation_does_not_reflect_secret(client, keys):
    for _ in range(5):
        assert client.post("/api/auth/login", json={"access_key": "x" * 43}, headers=HEADERS).status_code == 401
    assert client.post("/api/auth/login", json={"access_key": "x" * 43}, headers=HEADERS).status_code == 429
    access.buckets.clear()
    response = client.post("/api/auth/login", json={"access_key": "SECRET-INVALID-INPUT"}, headers=HEADERS)
    assert response.status_code == 422
    assert "SECRET-INVALID-INPUT" not in response.text


def test_local_mode_refuses_non_loopback_even_with_allowed_host():
    remote = TestClient(app, client=("192.0.2.1", 50000))
    assert remote.get("/api/auth/session").status_code == 403
    remote.close()


def test_triage_records_server_identity_not_client_claim(client, keys, session):
    from app.services.intelligence import upsert
    item = upsert(session, "osv", {"id": "OSV-identity"})
    session.commit()
    response = client.patch(f"/api/vulnerabilities/{item.id}/triage", json={"status": "investigating", "reason": "Test decision"}, headers=bearer(keys["analyst"]))
    assert response.status_code == 200
    event = session.scalar(select(Activity).where(Activity.kind == "triage"))
    assert event.data["actor"] == "analyst"
    assert event.data["request_id"] == response.headers["X-Request-ID"]


def test_api_request_and_expensive_operation_budgets_are_enforced(client, keys, monkeypatch):
    monkeypatch.setattr(settings, "requests_per_minute", 10)
    for _ in range(10):
        assert client.get("/api/projects", headers=bearer(keys["viewer"])).status_code == 200
    response = client.get("/api/projects", headers=bearer(keys["viewer"]))
    assert response.status_code == 429 and response.headers["Retry-After"] == "60"
    access.buckets.clear()
    monkeypatch.setattr("app.http_security.inflight_expensive", 4)
    response = client.post("/api/search/package", json={"ecosystem": "npm", "package": "test"}, headers=bearer(keys["analyst"]))
    assert response.status_code == 429


def test_source_payload_error_is_not_recorded_as_success_or_running(client, monkeypatch):
    async def invalid(*args):
        return [{"id": "UNTRUSTED\nID"}]
    monkeypatch.setattr("app.main.query_osv", invalid)
    response = client.post("/api/search/package", json={"ecosystem": "npm", "package": "test"}, headers=HEADERS)
    assert response.status_code == 502
    rows = {row["id"]: row for row in client.get("/api/sources").json()}
    assert rows["osv"]["status"] == "failed"


def test_slow_query_returns_safe_timeout_with_request_identifier(client, monkeypatch):
    import asyncio
    async def slow(*args):
        await asyncio.sleep(2)
        return []
    monkeypatch.setattr(settings, "request_timeout", 1)
    monkeypatch.setattr("app.main.query_osv", slow)
    response = client.post("/api/search/package", json={"ecosystem": "npm", "package": "test"}, headers=HEADERS)
    assert response.status_code == 504
    assert response.headers["X-Request-ID"]
    assert "Traceback" not in response.text


def test_security_headers_cover_rejections_and_invalid_content_types(client, keys):
    responses = [client.get("/api/projects"),
                 client.post("/api/projects", json={}, headers=bearer(keys["viewer"])),
                 client.post("/api/auth/login", content="private-input", headers={**HEADERS, "Content-Type": "text/plain"}),
                 client.post("/api/auth/login", json={"access_key": "private-input"}, headers=HEADERS)]
    assert [response.status_code for response in responses] == [401, 403, 415, 422]
    for response in responses:
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Request-ID"]
        assert "private-input" not in response.text


async def test_unexpected_exception_has_safe_body_and_headers():
    from starlette.requests import Request
    from app.http_security import security_boundary

    async def failing(_):
        raise RuntimeError("PRIVATE-EXCEPTION-DETAIL")

    request = Request({"type": "http", "method": "GET", "scheme": "http", "path": "/api/auth/session",
                       "headers": [(b"host", b"testserver")], "client": ("127.0.0.1", 1234), "query_string": b""})
    response = await security_boundary(request, failing)
    assert response.status_code == 500
    assert b"PRIVATE-EXCEPTION-DETAIL" not in response.body
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Request-ID"]
    assert response.headers["X-Frame-Options"] == "DENY"


def test_sse_budget_rejects_additional_connections(client, keys, monkeypatch):
    monkeypatch.setitem(access.stream_counts, "viewer", 4)
    response = client.get("/api/events", headers=bearer(keys["viewer"]))
    assert response.status_code == 429
