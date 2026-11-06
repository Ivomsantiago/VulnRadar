import csv
import io
from datetime import datetime, timedelta, timezone
import httpx
import pytest
from sqlalchemy import select, func
from sqlalchemy.orm import sessionmaker
from app import radar
from app.db import Activity, Advisory, RadarCollection, Source, Vulnerability
from app.services.intelligence import upsert
from test_operations_v2 import HEADERS

FIXED = datetime(2026, 11, 6, 12, tzinfo=timezone.utc)


def nvd(identifier="CVE-2099-RADAR-CRITICAL", age=2, severity="CRITICAL", score=9.8):
    return {
        "cve": {
            "id": identifier,
            "published": (FIXED - timedelta(hours=age)).isoformat(),
            "lastModified": FIXED.isoformat(),
            "descriptions": [{"lang": "en", "value": "Explicit test fixture"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": severity}}]},
        }
    }


def seed(session, monkeypatch):
    monkeypatch.setattr(radar, "now", lambda: FIXED)
    for identifier, severity, age in [
        ("CRIT", "CRITICAL", 2),
        ("HIGH", "HIGH", 3),
        ("MONTH", "HIGH", 24 * 15),
        ("OLD", "CRITICAL", 24 * 100),
        ("LOW", "LOW", 1),
        ("FUTURE", "CRITICAL", -1),
    ]:
        session.add(
            Vulnerability(
                id=identifier,
                title="=FORMULA" if identifier == "HIGH" else identifier,
                severity=severity,
                published=(FIXED - timedelta(hours=age)).isoformat(),
                modified=(FIXED - timedelta(minutes=10)).isoformat(),
                cvss=9.8 if severity == "CRITICAL" else 7.5,
                epss=0.9 if identifier == "HIGH" else None,
            )
        )
    session.add(Vulnerability(id="OFFSET", title="Offset", severity="HIGH", published="2026-11-05T10:00:00-03:00", modified=FIXED.isoformat()))
    session.add(Vulnerability(id="UNDATED", title="No date", severity="CRITICAL"))
    session.commit()


def test_exact_24h_month_custom_windows_and_critical_high_priority(client, session, monkeypatch):
    seed(session, monkeypatch)
    result = client.get("/api/radar").json()
    assert [row["id"] for row in result["items"]] == ["CRIT", "HIGH", "OFFSET"]
    assert result["summary"]["total"] == 4 and result["summary"]["critical"] == 1 and result["summary"]["high"] == 2
    monthly = client.get("/api/radar?period=30d").json()
    assert "MONTH" in [row["id"] for row in monthly["items"]]
    assert "OLD" not in [row["id"] for row in monthly["items"]]
    custom = client.get("/api/radar", params={"period": "custom", "since": (FIXED - timedelta(days=20)).isoformat(), "until": (FIXED - timedelta(days=10)).isoformat()}).json()
    assert [row["id"] for row in custom["items"]] == ["MONTH"]
    assert client.get("/api/radar?period=custom").status_code == 422
    assert client.get("/api/radar", params={"since": (FIXED - timedelta(days=400)).isoformat()}).status_code == 422
    # Modified means exactly that; an old publication updated now remains discoverable.
    assert "OLD" in [row["id"] for row in client.get("/api/radar?basis=modified").json()["items"]]


def test_filtered_queue_and_export_share_the_period_and_do_not_mark_app_exposure(client, session, monkeypatch):
    seed(session, monkeypatch)
    response = client.post("/api/radar/queue", json={"identifiers": ["CRIT", "HIGH"]}, headers=HEADERS)
    assert response.status_code == 200 and response.json()["updated"] == 2
    assert client.post("/api/radar/queue", json={"identifiers": ["CRIT", "HIGH"]}, headers=HEADERS).json()["updated"] == 0
    queued = client.get("/api/radar?state=queued").json()
    assert queued["total"] == 2 and queued["summary"]["queued"] == 2
    assert client.get("/api/exposure").json()["state"] == "no_projects"
    csv_response = client.get("/api/radar?state=queued&format=csv")
    exported = list(csv.DictReader(io.StringIO(csv_response.text)))
    assert {row["id"] for row in exported} == {"CRIT", "HIGH"}
    assert next(row for row in exported if row["id"] == "HIGH")["title"] == "'=FORMULA"
    assert session.scalar(select(func.count()).select_from(Activity).where(Activity.kind == "triage")) == 2
    assert client.post("/api/radar/queue", json={"identifiers": ["MISSING", "CRIT"]}, headers=HEADERS).status_code == 404


async def test_requested_collection_uses_publication_window_deduplicates_and_keeps_checkpoint(session, monkeypatch):
    monkeypatch.setattr(radar, "now", lambda: FIXED)
    monkeypatch.setattr(radar, "Session", sessionmaker(session.get_bind(), expire_on_commit=False))
    state = Source(id="nvd", checkpoint="2026-01-01T00:00:00Z", status="success")
    session.add(state)
    job = RadarCollection(since=FIXED - timedelta(days=30), until=FIXED, basis="published", enrich=True, progress={"sources": {}, "pages": 0, "fetched": 0})
    session.add(job)
    session.commit()
    calls = []

    async def request(client, method, url, **kwargs):
        calls.append((url, kwargs))
        if url == radar.URLS["nvd"]:
            assert "pubStartDate" in kwargs["params"] and "lastModStartDate" not in kwargs["params"]
            return httpx.Response(200, json={"vulnerabilities": [nvd()], "totalResults": 1})
        if url == radar.URLS["github"]:
            assert "published" in kwargs["params"] and ".." in kwargs["params"]["published"]
            return httpx.Response(
                200,
                json=[
                    {
                        "ghsa_id": "GHSA-radar-test",
                        "identifiers": [{"value": "CVE-2099-RADAR-CRITICAL"}],
                        "summary": "Fixture GitHub",
                        "severity": "critical",
                        "published_at": (FIXED - timedelta(hours=2)).isoformat(),
                        "updated_at": FIXED.isoformat(),
                    }
                ],
            )
        assert url == radar.URLS["epss"]
        return httpx.Response(200, json={"data": [{"cve": "CVE-2099-RADAR-CRITICAL", "epss": "0.9", "date": "2026-11-06"}]})

    async def kev(client):
        return {"vulnerabilities": [{"cveID": "CVE-2099-RADAR-CRITICAL", "dateAdded": "2026-11-06"}]}

    monkeypatch.setattr(radar, "request", request)
    monkeypatch.setattr(radar, "fetch_kev", kev)
    await radar.run_collection(job.id)
    session.expire_all()
    saved = session.get(RadarCollection, job.id)
    assert saved.status == "success" and saved.progress["sources"]["nvd"]["pages"] == 1
    assert session.scalar(select(func.count()).select_from(Vulnerability)) == 1
    vulnerability = session.scalar(select(Vulnerability))
    assert vulnerability.kev and vulnerability.epss == 0.9
    assert session.get(Source, "nvd").checkpoint == "2026-01-01T00:00:00Z"
    assert all(value["status"] == "success" for value in saved.progress["sources"].values())


async def test_partial_collection_retains_pages_and_survives_source_failure(session, monkeypatch):
    monkeypatch.setattr(radar, "Session", sessionmaker(session.get_bind(), expire_on_commit=False))
    job = RadarCollection(since=FIXED - timedelta(days=1), until=FIXED, basis="published", enrich=False, progress={"sources": {}, "pages": 0, "fetched": 0})
    session.add(job)
    session.commit()

    async def request(client, method, url, **kwargs):
        if url == radar.URLS["nvd"] and kwargs["params"]["startIndex"] == 0:
            return httpx.Response(200, json={"vulnerabilities": [nvd()], "totalResults": 2001})
        raise httpx.ConnectError("Do not persist upstream bodies or secrets")

    async def pause(_):
        return None

    monkeypatch.setattr(radar, "request", request)
    monkeypatch.setattr(radar.asyncio, "sleep", pause)
    await radar.run_collection(job.id)
    session.expire_all()
    saved = session.get(RadarCollection, job.id)
    assert saved.status == "partial"
    assert saved.progress["sources"]["nvd"]["pages"] == 1
    assert saved.progress["sources"]["github"]["status"] == "failed"
    assert session.scalar(select(func.count()).select_from(Advisory)) == 1
    assert "secrets" not in str(saved.progress)


async def test_custom_large_interval_is_chunked_and_updated_basis_is_explicit(session, monkeypatch):
    job = RadarCollection(since=FIXED - timedelta(days=180), until=FIXED, basis="modified", enrich=False, progress={"sources": {}, "pages": 0, "fetched": 0})
    session.add(job)
    session.commit()
    ranges = []

    async def request(client, method, url, **kwargs):
        params = kwargs["params"]
        start = datetime.fromisoformat(params["lastModStartDate"])
        end = datetime.fromisoformat(params["lastModEndDate"])
        assert end - start <= timedelta(days=119)
        ranges.append((start, end))
        return httpx.Response(200, json={"vulnerabilities": [], "totalResults": 0})

    async def pause(_):
        return None

    monkeypatch.setattr(radar, "request", request)
    monkeypatch.setattr(radar.asyncio, "sleep", pause)
    async with httpx.AsyncClient() as client:
        result = await radar.collect_source(session, job, "nvd", client, set())
    assert result["pages"] == 2 and ranges[0][1] == ranges[1][0]


def test_undated_kev_record_receives_real_publication_date(session):
    session.add(Vulnerability(id="CVE-2099-RADAR-CRITICAL", title="KEV record", severity="UNKNOWN"))
    from app.db import Alias

    session.flush()
    session.add(Alias(id="CVE-2099-RADAR-CRITICAL", vulnerability_id="CVE-2099-RADAR-CRITICAL"))
    session.flush()
    value = upsert(session, "nvd", nvd())
    assert value.published == nvd()["cve"]["published"]


def test_recovery_preserves_completed_pages(session):
    job = RadarCollection(since=FIXED - timedelta(days=1), until=FIXED, status="running", progress={"fetched": 10, "pages": 1})
    session.add(job)
    session.commit()
    radar.recover_collections(session)
    assert job.status == "failed" and job.progress["fetched"] == 10


async def test_cancelled_requested_collection_persists_state(session, monkeypatch):
    import asyncio

    monkeypatch.setattr(radar, "Session", sessionmaker(session.get_bind(), expire_on_commit=False))
    job = RadarCollection(since=FIXED - timedelta(days=1), until=FIXED, enrich=False, progress={"sources": {}, "pages": 0, "fetched": 0})
    session.add(job)
    session.commit()
    started = asyncio.Event()

    async def blocked(*args, **kwargs):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(radar, "request", blocked)
    task = asyncio.create_task(radar.run_collection(job.id))
    await asyncio.wait_for(started.wait(), 3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    session.expire_all()
    assert session.get(RadarCollection, job.id).status == "cancelled"


async def test_github_collection_follows_after_cursor_instead_of_repeating_page_one(session, monkeypatch):
    job = RadarCollection(since=FIXED - timedelta(days=30), until=FIXED, basis="published", enrich=False, progress={"sources": {}, "pages": 0, "fetched": 0})
    session.add(job)
    session.commit()
    cursors = []

    async def request(client, method, url, **kwargs):
        params = kwargs["params"]
        assert "page" not in params
        assert params["published"].endswith("Z") and "+" not in params["published"]
        cursors.append(params.get("after"))
        identifier = "GHSA-first" if not params.get("after") else "GHSA-second"
        raw = {"ghsa_id": identifier, "summary": "Cursor fixture", "severity": "high", "published_at": (FIXED - timedelta(hours=2)).isoformat(), "updated_at": FIXED.isoformat()}
        headers = {"Link": '<https://api.github.com/advisories?after=opaque-cursor&per_page=100>; rel="next"'} if not params.get("after") else {}
        return httpx.Response(200, json=[raw], headers=headers)

    async def pause(_):
        return None

    monkeypatch.setattr(radar, "request", request)
    monkeypatch.setattr(radar.asyncio, "sleep", pause)
    async with httpx.AsyncClient() as client:
        result = await radar.collect_source(session, job, "github", client, set())
    assert cursors == [None, "opaque-cursor"] and result["new"] == 2 and result["pages"] == 2


def test_repeated_github_cursor_is_incomplete():
    from app.services.intelligence import github_next_page

    response = httpx.Response(200, headers={"Link": '<https://api.github.com/advisories?after=same>; rel="next"'})
    seen = set()
    assert github_next_page(response, seen) == {"after": "same"}
    with pytest.raises(ValueError, match="repetido"):
        github_next_page(response, seen)


def test_unrated_mirror_cannot_hide_known_critical_and_rating_can_be_revised(session):
    raw = nvd()
    vulnerability = upsert(session, "nvd", raw)
    upsert(session, "github", {"ghsa_id": "GHSA-unrated-mirror", "identifiers": [{"value": raw["cve"]["id"]}], "severity": "unknown", "summary": "Unrated mirror"})
    session.commit()
    assert vulnerability.severity == "CRITICAL" and vulnerability.cvss == 9.8
    raw["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"] = {"baseScore": 7.5, "baseSeverity": "HIGH"}
    upsert(session, "nvd", raw)
    assert vulnerability.severity == "HIGH" and vulnerability.cvss == 7.5


def test_repair_old_unrated_cache_preserves_triage_and_raw_sources(session):
    from app.services.intelligence import repair_unrated_assessments

    raw = nvd()
    vulnerability = upsert(session, "nvd", raw)
    vulnerability.severity, vulnerability.triage = "UNKNOWN", "planned"
    session.commit()
    repair_unrated_assessments(session)
    assert vulnerability.severity == "CRITICAL" and vulnerability.cvss == 9.8
    assert vulnerability.triage == "planned"
    assert session.scalar(select(Advisory)).payload == raw


def test_priority_does_not_attach_lower_source_cvss_to_higher_severity(session):
    raw = nvd()
    raw["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"] = {"baseScore": 3.0, "baseSeverity": "LOW"}
    vulnerability = upsert(session, "github", {"ghsa_id": "GHSA-high-without-score", "identifiers": [{"value": raw["cve"]["id"]}], "severity": "high", "summary": "High severity without a numerical score"})
    upsert(session, "nvd", raw)
    assert vulnerability.severity == "HIGH" and vulnerability.cvss is None
