import pytest
from app.request_limits import RequestBodyLimit


@pytest.mark.asyncio
@pytest.mark.parametrize("headers,chunks,status", [
    ([], [b"123", b"456"], 413),
    ([(b"content-length", b"1")], [b"123456"], 413),
    ([(b"content-length", b"-1")], [], 400),
    ([(b"content-length", b"x")], [], 400),
    ([], [b"12", b"345"], 204),
])
async def test_actual_body_limit(headers, chunks, status):
    messages = []
    pending = [{"type": "http.request", "body": chunk, "more_body": index < len(chunks) - 1} for index, chunk in enumerate(chunks)]

    async def receive():
        return pending.pop(0)

    async def send(message):
        messages.append(message)

    async def endpoint(scope, receive, send):
        assert (await receive())["body"] == b"12345"
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    await RequestBodyLimit(endpoint, 5)({"type": "http", "method": "POST", "headers": headers}, receive, send)
    assert messages[0]["status"] == status


def test_retired_oci_cannot_queue(client, monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "installed")
    response = client.post("/api/projects/1/oci", json={"image": "alpine:3", "engine": "trivy"}, headers={"X-VulnRadar-Client": "web"})
    assert response.status_code == 410


@pytest.mark.asyncio
async def test_retired_worker_cannot_spawn(monkeypatch):
    from app.services.oci import oci
    with pytest.raises(ValueError, match="descontinuada"):
        await oci("alpine:3", "grype")


@pytest.mark.parametrize("reverse", [False, True])
def test_source_summary_independent_of_ingestion_order(session, reverse):
    from app.services.intelligence import upsert
    records = [
        ("osv", {"id": "GHSA-fixture", "aliases": ["CVE-2099-5000"], "summary": "Package evidence", "details": "Package detail", "database_specific": {"severity": "HIGH"}, "published": "2099-01-01T00:00:00Z", "modified": "2099-02-01T00:00:00Z"}),
        ("nvd", {"cve": {"id": "CVE-2099-5000", "descriptions": [], "lastModified": "2099-01-01T00:00:00Z"}}),
    ]
    for source, raw in reversed(records) if reverse else records:
        result = upsert(session, source, raw)
    assert result.severity == "HIGH"
    assert result.description == "Package detail"
    assert result.published == "2099-01-01T00:00:00+00:00"
    assert result.modified == "2099-02-01T00:00:00+00:00"


def test_source_revision_can_reduce_summary_severity(session):
    from app.services.intelligence import upsert
    raw = {"id": "OSV-fixture", "database_specific": {"severity": "CRITICAL"}, "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    result = upsert(session, "osv", raw)
    assert result.cvss == 9.8
    result = upsert(session, "osv", {"id": raw["id"], "database_specific": {"severity": "LOW"}})
    assert result.severity == "LOW"
    assert result.cvss is None


def test_quality_does_not_invent_missing_metrics(client, session):
    from app.services.intelligence import upsert
    upsert(session, "osv", {"id": "OSV-quality"})
    session.commit()
    result = client.get("/api/intelligence/quality").json()
    assert result["total"] == 1
    assert result["missing"] == {"severity": 1, "cvss": 1, "epss": 1, "published": 1, "description": 1}
    assert result["sources"] == [{"source": "osv", "advisories": 1}]


def test_freshness_uses_saved_schedule_and_osv_stays_on_demand(client, session):
    from datetime import timedelta
    from app.db import Source, SyncRun, PlatformSetting, now
    session.add(PlatformSetting(key="scheduler", value={"enabled": True, "interval_minutes": 1440}))
    for name in ("nvd", "osv"):
        session.add(Source(id=name, status="success"))
        session.add(SyncRun(source=name, status="success", completed_at=now() - timedelta(hours=5)))
    session.commit()
    rows = {row["id"]: row for row in client.get("/api/sources").json()}
    assert rows["nvd"]["health"] == "healthy"
    assert rows["osv"]["health"] == "healthy"


@pytest.mark.asyncio
async def test_connector_retries_transport_failure_without_hiding_permanent_failure(monkeypatch):
    import httpx
    from app.services.intelligence import request
    attempts = []

    async def sleep(_):
        pass

    monkeypatch.setattr("app.services.intelligence.asyncio.sleep", sleep)

    def handler(req):
        attempts.append(req)
        raise httpx.ConnectError("test transport unavailable", request=req)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.ConnectError):
            await request(client, "GET", "https://source.example.test")
    assert len(attempts) == 4
