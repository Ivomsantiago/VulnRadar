"""Test-only ASGI entrypoint; never used by the production launcher or image."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.main import app  # noqa: E402,F401
import app.main as main_module  # noqa: E402
import app.services.scanner as scanner  # noqa: E402
import app.services.monitoring as monitoring  # noqa: E402


async def mock_osv(ecosystem, package, version):
    # Explicitly fictional data, isolated to the disposable test server database.
    if package != "lodash":
        return []
    return [{"id": "OSV-E2E-FIXTURE", "aliases": ["CVE-2099-E2E-FIXTURE"], "summary": "Fictional advisory used only by hermetic browser tests", "details": "Not production intelligence.", "database_specific": {"severity": "HIGH"}, "published": "2026-01-01T00:00:00Z", "affected": [{"package": {"ecosystem": ecosystem, "name": package}, "versions": [version] if version else [], "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "99.0.0"}]}]}], "references": []}]


scanner.query_osv = mock_osv
main_module.query_osv = mock_osv
monitoring.query_osv = mock_osv
