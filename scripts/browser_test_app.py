"""Test-only ASGI entrypoint; never used by the production launcher or image."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.main import app  # noqa: E402,F401
import app.main as main_module  # noqa: E402
import app.services.scanner as scanner  # noqa: E402
import app.services.monitoring as monitoring  # noqa: E402
import app.radar as radar_module  # noqa: E402
from app.config import settings  # noqa: E402


async def mock_osv(ecosystem, package, version):
    # Explicitly fictional data, isolated to the disposable test server database.
    if package != "lodash" or version == "99.0.0":
        return []
    return [{"id": "OSV-E2E-FIXTURE", "aliases": ["CVE-2099-E2E-FIXTURE"], "summary": "Fictional advisory used only by hermetic browser tests", "details": "Not production intelligence.", "database_specific": {"severity": "HIGH"}, "published": "2026-01-01T00:00:00Z", "affected": [{"package": {"ecosystem": ecosystem, "name": package}, "versions": [version] if version else [], "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}]}], "references": []}]


scanner.query_osv = mock_osv
main_module.query_osv = mock_osv
monitoring.query_osv = mock_osv
settings.osv_batch = False

# CPE explicitamente fictício apenas no entrypoint de testes descartáveis.
from contextlib import asynccontextmanager  # noqa: E402
from app.db import Session, Source, now  # noqa: E402
from app.services.intelligence import upsert  # noqa: E402
from datetime import datetime, timedelta  # noqa: E402
import httpx  # noqa: E402

production_lifespan = app.router.lifespan_context


def radar_fixture(monthly=False):
    return {"cve": {"id": "CVE-2099-RADAR-MONTH" if monthly else "CVE-2099-PRODUCT-FIXTURE", "descriptions": [{"lang": "en", "value": "FICTIONAL monthly high advisory" if monthly else "FICTIONAL product used only by disposable browser tests"}], "published": (now() - timedelta(days=10) if monthly else now() - timedelta(hours=2)).isoformat(), "lastModified": (now() - timedelta(hours=1)).isoformat(), "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1 if monthly else 9.8, "baseSeverity": "HIGH" if monthly else "CRITICAL"}}]}, "configurations": [] if monthly else [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:fixture_vendor:fixture_runtime:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}]}]}]}}


async def mock_range_request(client, method, url, **kwargs):
    params = kwargs.get("params", {})
    if url == radar_module.URLS["nvd"]:
        basis = "published" if "pubStartDate" in params else "lastModified"
        prefix = "pub" if basis == "published" else "lastMod"
        start, end = datetime.fromisoformat(params[prefix + "StartDate"]), datetime.fromisoformat(params[prefix + "EndDate"])
        rows = [raw for raw in [radar_fixture(), radar_fixture(True)] if start <= datetime.fromisoformat(raw["cve"][basis]) <= end]
        return httpx.Response(200, json={"vulnerabilities": rows, "totalResults": len(rows)})
    if url == radar_module.URLS["github"]:
        raw = radar_fixture()["cve"]
        return httpx.Response(200, json=[{"ghsa_id": "GHSA-radar-fixture", "identifiers": [{"value": raw["id"]}], "summary": "FICTIONAL radar advisory for browser tests", "severity": "critical", "cvss": {"score": 9.8}, "published_at": raw["published"], "updated_at": raw["lastModified"]}])
    return httpx.Response(200, json={"data": [{"cve": value, "epss": "0.8", "date": now().date().isoformat()} for value in params.get("cve", "").split(",") if value]})


async def mock_range_kev(client):
    return {"vulnerabilities": [{"cveID": "CVE-2099-PRODUCT-FIXTURE", "dateAdded": now().date().isoformat()}]}


radar_module.request = mock_range_request
radar_module.fetch_kev = mock_range_kev


@asynccontextmanager
async def test_lifespan(application):
    async with production_lifespan(application):
        with Session() as session:
            raw = radar_fixture()
            upsert(session, "nvd", raw)
            session.add(Source(id="nvd", status="success", last_run=now().isoformat(), count=1))
            session.commit()
        yield


app.router.lifespan_context = test_lifespan
