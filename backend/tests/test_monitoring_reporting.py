from app.db import Activity, Watch, Vulnerability
from app.services.monitoring import check_watch, prioritize
from app.services.reporting import cyclone_dx, sarif
from sqlalchemy import select, func
from test_intelligence import osv


def test_priority_unknown_and_known_exploitation():
    vulnerability = Vulnerability(id="fixture", title="test", kev=False)
    assert prioritize(vulnerability)["classification"] == "Dados insuficientes"
    vulnerability.kev = True
    assert prioritize(vulnerability)["classification"] == "Investigação imediata"


async def test_watchlist_deduplicates_alerts(session, monkeypatch):
    watch = Watch(ecosystem="npm", package="fixture", version="1.0.0")
    session.add(watch)
    session.commit()

    async def query(*args):
        return [osv()]

    monkeypatch.setattr("app.services.monitoring.query_osv", query)
    await check_watch(session, watch.id)
    await check_watch(session, watch.id)
    assert session.scalar(select(func.count()).select_from(Activity).where(Activity.subject.like("watch:%"))) == 1


def test_exports_retain_component_identity_and_location():
    bom = cyclone_dx([{"ecosystem": "npm", "package": "@scope/name", "version": "1.0.0"}])
    assert bom["components"][0]["purl"] == "pkg:npm/%40scope/name@1.0.0"
    report = sarif([{"check_id": "fixture-rule", "path": "src/test.py", "start": {"line": 3}, "extra": {"message": "fixture", "severity": "ERROR"}}])
    assert report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 3
