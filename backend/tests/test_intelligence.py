import httpx
from sqlalchemy import select, func
from app.db import Advisory, Alias, Vulnerability
from app.services.intelligence import normalize, request, upsert, sync_source


def osv(identifier="GHSA-test-one", aliases=None):
    return {
        "id": identifier,
        "aliases": aliases or ["CVE-2099-1001"],
        "summary": "Test advisory",
        "details": "Fixture only",
        "database_specific": {"severity": "HIGH"},
        "affected": [],
    }


def test_alias_deduplication_and_source_evidence(session):
    first = upsert(session, "osv", osv())
    second = upsert(session, "osv", osv("OTHER-ID"))
    session.commit()
    assert first.id == second.id
    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 1
    assert session.scalar(select(func.count()).select_from(Advisory)) == 2
    assert session.get(Alias, "OTHER-ID").vulnerability_id == first.id


def test_titles_do_not_merge(session):
    upsert(session, "osv", osv("ONE", ["CVE-2099-1001"]))
    upsert(session, "osv", osv("TWO", ["CVE-2099-1002"]))
    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 2


def test_bridging_alias(session):
    upsert(session, "osv", osv("ONE", ["CVE-2099-1001"]))
    upsert(session, "osv", osv("TWO", ["CVE-2099-1002"]))
    upsert(session, "osv", osv("ONE", ["TWO", "CVE-2099-1001", "CVE-2099-1002"]))
    session.commit()
    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 1
    assert len(set(session.scalars(select(Alias.vulnerability_id)))) == 1


def test_missing_cvss_unknown():
    item = normalize("nvd", {"cve": {"id": "CVE-2099-1", "descriptions": []}})
    assert item["cvss"] is None and item["severity"] == "UNKNOWN"


async def test_retry_rate_limit(monkeypatch):
    calls = []

    async def sleep(_):
        pass

    monkeypatch.setattr("app.services.intelligence.asyncio.sleep", sleep)

    def handler(req):
        calls.append(req)
        return httpx.Response(429 if len(calls) == 1 else 200, json={"ok": True}, headers={"Retry-After": "1"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response = await request(client, "GET", "https://example.test")
    assert response.json() == {"ok": True} and len(calls) == 2


async def test_failed_sync_preserves_data(session, monkeypatch):
    upsert(session, "osv", osv())
    session.commit()

    async def fail(*args, **kwargs):
        raise httpx.ConnectError("fixture failure")

    monkeypatch.setattr("app.services.intelligence.request", fail)
    result = await sync_source(session, "nvd")
    assert result.status == "failed" and result.checkpoint is None
    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 1


async def test_kev_uses_official_mirror_on_primary_failure():
    from app.services.intelligence import fetch_kev, KEV_MIRROR, URLS

    destinations = []

    def handler(req):
        destinations.append(str(req.url))
        if str(req.url) == URLS["kev"]:
            return httpx.Response(403)
        assert str(req.url) == KEV_MIRROR
        return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2099-1001"}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        data = await fetch_kev(client)
    assert len(data["vulnerabilities"]) == 1
    assert destinations == [URLS["kev"], KEV_MIRROR]


def test_osv_cvss_vector_is_computed_and_malformed_vector_stays_unknown():
    raw = osv()
    raw["database_specific"] = {}
    raw["severity"] = [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
    item = normalize("osv", raw)
    assert item["cvss"] == 9.8 and item["severity"] == "CRITICAL"
    raw["severity"][0]["score"] = "invalid"
    item = normalize("osv", raw)
    assert item["cvss"] is None and item["severity"] == "UNKNOWN"


def test_moderate_source_severity_maps_to_medium_without_losing_original(session):
    raw = osv()
    raw["database_specific"]["severity"] = "MODERATE"
    item = upsert(session, "osv", raw)
    session.commit()
    assert item.severity == "MEDIUM"
    advisory = session.scalar(select(Advisory))
    assert advisory.payload["database_specific"]["severity"] == "MODERATE"
