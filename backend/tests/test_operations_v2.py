import copy
import pytest
from sqlalchemy import func, select
from app.db import Activity, Finding, FindingObservation, InventoryComponent, Project, Scan, Vulnerability
from app.services.findings import backfill, index_scan
from app.services.intelligence import upsert
from test_intelligence import osv

HEADERS = {"X-VulnRadar-Client": "web"}


def make_scan(session, project=None, raw=None, package="fixture", status="completed", version="1.0.0", warnings=None, kind="sca"):
    if project is None:
        project = Project(name="Test application", path="/fixture-only")
        session.add(project)
        session.flush()
    dependency = {"ecosystem": "npm", "package": package, "version": version, "file": "package-lock.json", "direct": True, "query_status": "complete"}
    advisory = raw or osv()
    result = {
        "inventory": [dependency],
        "findings": [{"dependency": dependency, "advisory": advisory}],
        "warnings": warnings or [],
        "engine": "OSV",
        "coverage": "partial" if warnings else "complete",
    }
    scan = Scan(project_id=project.id, kind=kind, status=status, result=result)
    session.add(scan)
    session.flush()
    return scan


def test_global_advisory_never_becomes_exposure(client, session):
    upsert(session, "osv", osv())
    session.commit()
    assert client.get("/api/dashboard").json()["total"] == 1
    exposure = client.get("/api/exposure").json()
    assert exposure["relevant_vulnerabilities"] == 0
    assert exposure["state"] == "no_projects"
    assert client.get("/api/findings").json()["total"] == 0


def test_indexing_deduplicates_exposure_and_preserves_scan_evidence(client, session):
    raw = osv()
    raw["affected"] = [{"package": {"ecosystem": "npm", "name": "fixture"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]
    scan = make_scan(session, raw=raw)
    index_scan(session, scan)
    session.commit()
    index_scan(session, scan)
    assert session.scalar(select(func.count()).select_from(Finding)) == 1
    assert session.scalar(select(func.count()).select_from(FindingObservation)) == 1
    assert session.scalar(select(func.count()).select_from(InventoryComponent)) == 1
    finding = client.get("/api/findings").json()["items"][0]
    assert finding["project_name"] == "Test application"
    assert finding["fixed_versions"] == ["2.0.0"]
    assert client.get("/api/exposure").json()["relevant_vulnerabilities"] == 1
    assert client.get("/api/vulnerabilities/CVE-2099-1001").json()["related_projects"][0]["version"] == "1.0.0"
    assert client.get("/api/inventory").json()["total"] == 1
    assert client.get("/api/technologies").json()["items"][0]["package"] == "fixture"
    assert client.get("/api/findings?scan_id=999").json()["total"] == 0
    assert client.get("/api/findings?scan_id=" + str(scan.id)).json()["total"] == 1


def test_partial_scan_cannot_resolve_previous_findings(session):
    first = make_scan(session)
    index_scan(session, first)
    session.commit()
    second = make_scan(session, project=session.get(Project, first.project_id), status="partial", warnings=["OSV unavailable"])
    second.result = {**second.result, "findings": []}
    index_scan(session, second)
    session.commit()
    finding = session.scalar(select(Finding))
    assert finding.status == "new"
    assert second.result["comparison"]["comparable"] is False


def test_complete_comparable_scan_resolves_missing_finding_and_reopens_on_reappearance(session):
    first = make_scan(session)
    index_scan(session, first)
    session.commit()
    second = make_scan(session, project=session.get(Project, first.project_id))
    second.result = {**second.result, "findings": []}
    index_scan(session, second)
    session.commit()
    finding = session.scalar(select(Finding))
    assert finding.status == "resolved"
    assert second.result["comparison"]["resolved"] == 1
    third = make_scan(session, project=session.get(Project, first.project_id))
    index_scan(session, third)
    session.commit()
    assert finding.status == "new"
    assert session.scalar(select(func.count()).select_from(Finding)) == 1
    assert session.scalar(select(func.count()).select_from(Activity).where(Activity.kind == "finding.reopened")) == 1


def test_triage_is_project_scoped_and_requires_justification(client, session):
    scan = make_scan(session)
    index_scan(session, scan)
    session.commit()
    finding = session.scalar(select(Finding))
    assert client.patch(f"/api/findings/{finding.id}/triage", json={"status": "accepted", "reason": "x"}, headers=HEADERS).status_code == 422
    result = client.patch(f"/api/findings/{finding.id}/triage", json={"status": "remediating", "reason": "Valid evidence"}, headers=HEADERS)
    assert result.status_code == 200 and result.json()["status"] == "remediating"
    assert session.get(Vulnerability, finding.vulnerability_id).triage == "new"
    assert client.get(f"/api/findings/{finding.id}").json()["history"]


def test_backfill_legacy_scan_preserves_payload_and_does_not_duplicate_alerts(session):
    scan = make_scan(session)
    original = copy.deepcopy(scan.result)
    backfill(session)
    backfill(session)
    assert scan.result["inventory"] == original["inventory"]
    assert scan.result["findings"] == original["findings"]
    assert session.scalar(select(func.count()).select_from(Finding)) == 1
    assert session.scalar(select(func.count()).select_from(Activity).where(Activity.subject.like("finding:%"), Activity.kind == "alert")) == 0


def test_preferences_and_scheduler_validate_and_persist(client):
    assert client.patch("/api/preferences", json={"theme": "bad"}, headers=HEADERS).status_code == 422
    assert client.patch("/api/scheduler", json={"enabled": True, "interval_minutes": 0}, headers=HEADERS).status_code == 422
    assert client.patch("/api/preferences", json={"theme": "light", "density": "comfortable", "epss_threshold": 0.2}, headers=HEADERS).status_code == 200
    assert client.get("/api/preferences").json()["theme"] == "light"
    assert client.patch("/api/scheduler", json={"enabled": False, "interval_minutes": 30}, headers=HEADERS).status_code == 200
    assert client.get("/api/scheduler").json()["interval_minutes"] == 30


def test_directory_browser_cannot_escape_roots(client, tmp_path, monkeypatch):
    from app.config import settings

    root = tmp_path / "allowed"
    root.mkdir()
    child = root / "application"
    child.mkdir()
    monkeypatch.setattr(settings, "allowed_roots", [str(root)])
    assert client.get("/api/directories").json()["directories"][0]["path"] == str(root)
    assert client.get("/api/directories", params={"path": str(root)}).json()["directories"][0]["path"] == str(child)
    assert client.get("/api/directories", params={"path": str(tmp_path)}).status_code == 403


def test_watchlist_optional_version_and_settings(client):
    result = client.post("/api/watchlist", json={"ecosystem": "npm", "package": "fixture", "min_severity": "HIGH", "alerts_enabled": False}, headers=HEADERS)
    assert result.status_code == 201
    assert result.json()["alerts_enabled"] is False
    duplicate = client.post("/api/watchlist", json={"ecosystem": "npm", "package": "fixture"}, headers=HEADERS)
    assert duplicate.status_code == 409


@pytest.mark.parametrize("days", [7, 30, 60, 90])
def test_dashboard_accepts_numeric_query_period(client, days):
    response = client.get("/api/dashboard", params={"days": days})
    assert response.status_code == 200 and response.json()["period_days"] == days


def test_priority_preference_is_consistent_in_list_finding_and_advisory_detail(client, session):
    scan = make_scan(session)
    index_scan(session, scan)
    finding = session.scalar(select(Finding))
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    vulnerability.epss = 0.15
    session.commit()
    response = client.patch("/api/preferences", json={"theme": "dark", "density": "compact", "epss_threshold": 0.2}, headers=HEADERS)
    assert response.status_code == 200
    expected = "Monitoramento"
    assert client.get("/api/findings").json()["items"][0]["priority"]["classification"] == expected
    assert client.get(f"/api/findings/{finding.id}").json()["priority"]["classification"] == expected
    assert client.get(f"/api/vulnerabilities/{vulnerability.id}").json()["priority"]["classification"] == expected
