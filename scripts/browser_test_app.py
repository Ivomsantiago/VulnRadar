"""Test-only ASGI entrypoint; never used by the production launcher or image."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.main import app  # noqa: E402,F401
import app.main as main_module  # noqa: E402
import app.services.scanner as scanner  # noqa: E402
import app.services.monitoring as monitoring  # noqa: E402
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

production_lifespan = app.router.lifespan_context


@asynccontextmanager
async def test_lifespan(application):
    async with production_lifespan(application):
        with Session() as session:
            raw = {"cve": {"id": "CVE-2099-PRODUCT-FIXTURE", "descriptions": [{"lang": "en", "value": "FICTIONAL product used only by disposable browser tests"}], "lastModified": "2026-01-01T00:00:00Z", "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:fixture_vendor:fixture_runtime:*:*:*:*:*:*:*:*", "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}]}]}]}}
            upsert(session, "nvd", raw)
            session.add(Source(id="nvd", status="success", last_run=now().isoformat(), count=1))
            session.commit()
        yield


app.router.lifespan_context = test_lifespan
