from app.services.intelligence import upsert
from test_intelligence import osv

HEADERS = {"X-VulnRadar-Client": "web"}


def test_health_empty(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert client.get("/api/vulnerabilities").json()["total"] == 0


def test_csrf_host_origin(client):
    body = {"package": "lib", "ecosystem": "npm"}
    assert client.post("/api/watchlist", json=body).status_code == 403
    assert client.post("/api/watchlist", json=body, headers={**HEADERS, "Origin": "https://untrusted.test"}).status_code == 403
    assert client.get("/api/health", headers={"Host": "untrusted.test"}).status_code == 400


def test_watchlist_persistence(client):
    response = client.post("/api/watchlist", json={"package": "lib", "ecosystem": "npm", "version": "1.0.0"}, headers=HEADERS)
    assert response.status_code == 201
    identifier = response.json()["id"]
    assert len(client.get("/api/watchlist").json()) == 1
    assert client.delete(f"/api/watchlist/{identifier}", headers=HEADERS).status_code == 204
    assert client.get("/api/watchlist").json() == []


def test_filters_triage_csv(client, session):
    raw = osv()
    raw["summary"] = "=HYPERLINK(test)"
    item = upsert(session, "osv", raw)
    session.commit()
    assert client.get("/api/vulnerabilities?severity=LOW").json()["total"] == 0
    assert client.get("/api/vulnerabilities?q=GHSA-test-one").json()["total"] == 1
    assert client.get("/api/vulnerabilities?page=0").status_code == 422
    response = client.patch(f"/api/vulnerabilities/{item.id}/triage", json={"status": "investigating", "reason": "Evidence fixture"}, headers=HEADERS)
    assert response.json()["triage"] == "investigating"
    assert "'=HYPERLINK(test)" in client.get("/api/export?format=csv").text
    assert client.get(f"/api/vulnerabilities/{item.id}").json()["history"]


def test_incomplete_package_query(client, monkeypatch):
    async def fail(*args):
        raise RuntimeError("fixture")

    monkeypatch.setattr("app.main.query_osv", fail)
    response = client.post("/api/search/package", json={"ecosystem": "npm", "package": "lib", "version": "1"}, headers=HEADERS)
    assert response.status_code == 502


def test_package_identity_search_and_source_filters(client, session):
    raw = osv()
    raw["affected"] = [{"package": {"ecosystem": "npm", "name": "@scope/package"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]
    item = upsert(session, "osv", raw)
    session.commit()
    assert client.get("/api/vulnerabilities?q=%40scope%2Fpackage").json()["total"] == 1
    assert client.get("/api/vulnerabilities?ecosystem=PyPI").json()["total"] == 0
    assert client.get("/api/vulnerabilities?ecosystem=npm&source=osv").json()["total"] == 1
    detail = client.get(f"/api/vulnerabilities/{item.id}").json()
    assert detail["evidence"][0]["packages"][0]["fixed"] == ["2.0.0"]
