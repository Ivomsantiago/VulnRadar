import asyncio
import json
from datetime import timedelta, timezone
from sqlalchemy import select, func
from app.db import Finding, Project, Scan, now
from app.services.findings import index_scan
from app.services.scanner import parse_dependencies, sca
from test_operations_v2 import make_scan, HEADERS
from test_intelligence import osv


def test_nested_npm_dependency_is_not_direct(tmp_path):
    path = tmp_path / "package-lock.json"
    path.write_text(
        json.dumps({"packages": {"": {"devDependencies": {"lib": "1.0.0"}}, "node_modules/lib": {"version": "1.0.0"}, "node_modules/other/node_modules/lib": {"version": "1.0.0"}}})
    )
    items, _ = parse_dependencies(path)
    assert items[0]["direct"] is True and items[1]["direct"] is False


def test_sast_line_shift_preserves_identity_and_separate_duplicate_occurrences(session):
    project = Project(name="fixture", path="/fixture")
    session.add(project)
    session.flush()

    def scan(line):
        raw = {"check_id": "rule", "path": "a.py", "start": {"line": line}, "code_digest": "same-code", "extra": {"severity": "ERROR"}}
        value = Scan(project_id=project.id, kind="sast", status="completed", result={"findings": [raw, {**raw, "start": {"line": line + 3}}], "engine": "Semgrep", "warnings": []})
        session.add(value)
        session.flush()
        index_scan(session, value)
        session.commit()
        return value

    first = scan(2)
    second = scan(20)
    assert session.scalar(select(func.count()).select_from(Finding)) == 2
    assert second.result["comparison"]["persistent"] == 2 and second.result["comparison"]["new"] == 0
    assert first.indexed


def test_fixed_versions_are_restricted_to_matching_component(session):
    raw = osv()
    raw["affected"] = [
        {"package": {"ecosystem": "npm", "name": name}, "ranges": [{"events": [{"fixed": fixed}]}]} for name, fixed in [("fixture", "2.0.0"), ("unrelated", "99.0.0")]
    ]
    scan = make_scan(session, raw=raw)
    index_scan(session, scan)
    session.commit()
    assert session.scalar(select(Finding)).fixed_versions == ["2.0.0"]


async def test_sca_queries_are_deduplicated_and_bounded(tmp_path, monkeypatch):
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {f"node_modules/p{i}": {"version": "1.0.0"} for i in range(10)}}))
    active, maximum, calls = 0, 0, []

    async def query(*key):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        calls.append(key)
        await asyncio.sleep(0.01)
        active -= 1
        return []

    monkeypatch.setattr("app.services.scanner.query_osv", query)
    result = await sca(tmp_path)
    assert len(calls) == 10 and 1 < maximum <= 4 and result["coverage"] == "complete"


def test_risk_expiry_assignment_report_and_csv_safety(client, session):
    scan = make_scan(session)
    index_scan(session, scan)
    session.commit()
    finding = session.scalar(select(Finding))
    url = f"/api/findings/{finding.id}/triage"
    assert client.patch(url, json={"status": "accepted", "reason": "Test reason"}, headers=HEADERS).status_code == 422
    payload = {
        "status": "accepted",
        "reason": "Documented decision",
        "owner": "=FORMULA",
        "due_at": (now() - timedelta(days=1)).isoformat(),
        "risk_expires_at": (now() + timedelta(days=2)).isoformat(),
        "remediation_plan": "Update package",
    }
    response = client.patch(url, json=payload, headers=HEADERS)
    assert response.status_code == 200 and response.json()["owner"] == "=FORMULA"
    report = client.get("/api/reports/findings", params={"status": "accepted"}).json()
    assert report["total"] == 1 and report["items"][0]["overdue"] is False
    assert client.get("/api/reports/findings?status=resolved").json()["total"] == 0
    assert "'=FORMULA" in client.get("/api/reports/findings?format=csv").text
    finding.risk_expires_at = now() - timedelta(days=1)
    session.commit()
    following = make_scan(session, project=session.get(Project, scan.project_id))
    index_scan(session, following)
    session.commit()
    assert finding.status == "new" and following.result["comparison"]["reopened"] == 1


def test_remediation_and_report_dates_respect_timezone_offsets(client, session):
    scan = make_scan(session)
    index_scan(session, scan)
    session.commit()
    finding = session.scalar(select(Finding))
    url = f"/api/findings/{finding.id}/triage"
    # Wall time is later than UTC now, but the actual instant has expired.
    expired = (now() - timedelta(hours=1)).astimezone(timezone(timedelta(hours=5)))
    response = client.patch(url, json={"status": "accepted", "reason": "Offset regression", "risk_expires_at": expired.isoformat()}, headers=HEADERS)
    assert response.status_code == 422
    due = now() - timedelta(hours=1)
    response = client.patch(url, json={"status": "planned", "reason": "Offset regression", "due_at": due.astimezone(timezone(timedelta(hours=5))).isoformat()}, headers=HEADERS)
    assert response.status_code == 200
    session.expire_all()
    assert finding.due_at.replace(tzinfo=timezone.utc) == due
    assert client.get("/api/reports/findings").json()["items"][0]["overdue"] is True
    since = (finding.first_seen - timedelta(hours=1)).replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=5)))
    assert client.get("/api/reports/findings", params={"since": since.isoformat()}).json()["total"] == 1


async def test_osv_success_cache_is_bounded_and_returns_independent_payloads(monkeypatch):
    import httpx
    from app.services import intelligence

    intelligence._OSV_CACHE.clear()
    calls = []
    original = httpx.AsyncClient

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"vulns": [{"id": "TEST-CACHE"}]})

    monkeypatch.setattr(intelligence.httpx, "AsyncClient", lambda **kwargs: original(transport=httpx.MockTransport(handler)))
    first = await intelligence.query_osv("npm", "cache-fixture", "1.0.0")
    first[0]["id"] = "mutated"
    second = await intelligence.query_osv("npm", "cache-fixture", "1.0.0")
    assert second[0]["id"] == "TEST-CACHE" and len(calls) == 1
    intelligence._OSV_CACHE.clear()


async def test_running_scan_cancellation_is_persisted(session, tmp_path, monkeypatch):
    import pytest
    from sqlalchemy.orm import sessionmaker
    from app import workers
    from app.config import settings

    monkeypatch.setattr(settings, "allowed_roots", [str(tmp_path)])
    factory = sessionmaker(session.get_bind(), expire_on_commit=False)
    monkeypatch.setattr(workers, "Session", factory)
    started = asyncio.Event()

    async def blocked(root, progress):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(workers, "sca", blocked)
    project = Project(name="Cancellation fixture", path=str(tmp_path))
    session.add(project)
    session.flush()
    scan = Scan(project_id=project.id, kind="sca", result={})
    session.add(scan)
    session.commit()
    task = asyncio.create_task(workers.run_scan(scan.id))
    await asyncio.wait_for(started.wait(), 3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    session.expire_all()
    assert session.get(Scan, scan.id).status == "cancelled"
    assert session.get(Scan, scan.id).completed_at is not None
