from copy import deepcopy
from datetime import timedelta
import pytest
from sqlalchemy import select, func
from app.db import Finding, VexStatement, now
from app.services.findings import index_scan
from app.services.vex import import_vex, export_vex, component_purl
from app.services.usage import observe_imports
from test_operations_v2 import make_scan


def vex_document(finding):
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:test:fixture", "version": 1, "author": "Fixture issuer", "timestamp": (now() - timedelta(minutes=1)).isoformat(), "statements": [{"vulnerability": {"name": finding.vulnerability_id}, "products": [{"@id": component_purl(finding)}], "status": "not_affected", "justification": "vulnerable_code_not_in_execute_path", "impact_statement": "Fixture-only reviewed statement"}]}


def test_vex_is_version_bound_does_not_silently_apply_and_can_round_trip(session):
    scan = make_scan(session)
    index_scan(session, scan)
    session.commit()
    finding = session.scalar(select(Finding))
    document = vex_document(finding)
    import_vex(session, finding, document, "openvex", False, "")
    assert finding.status == "new"
    with pytest.raises(ValueError):
        export_vex(session, finding, "openvex")
    wrong = deepcopy(document)
    wrong["statements"][0]["products"][0]["@id"] += "-different-version"
    with pytest.raises(ValueError):
        import_vex(session, finding, wrong, "openvex", True, "Test review")
    assert finding.status == "new"
    import_vex(session, finding, document, "openvex", True, "Test review")
    assert finding.status == "not_applicable"
    assert export_vex(session, finding, "openvex")["statements"][0]["justification"] == "vulnerable_code_not_in_execute_path"
    cdx = export_vex(session, finding, "cyclonedx")
    from app.services.schema_validation import cyclonedx_validator
    assert cyclonedx_validator().is_valid(cdx)
    import_vex(session, finding, cdx, "cyclonedx", True, "Round trip reviewed")
    assert session.scalar(select(func.count()).select_from(VexStatement)) == 3
    finding.status = "new"
    with pytest.raises(ValueError):
        export_vex(session, finding, "openvex")


def test_usage_reports_observation_and_unknown_without_executing_code(tmp_path):
    (tmp_path / "main.py").write_text("import requests\nraise RuntimeError('fixture must never execute')\n")
    (tmp_path / "main.ts").write_text("import { x } from '@scope/lib/path'; const y = require('lodash/fp');")
    inventory = [{"ecosystem": "PyPI", "package": "requests"}, {"ecosystem": "npm", "package": "lodash"}, {"ecosystem": "npm", "package": "@scope/lib"}, {"ecosystem": "Maven", "package": "vendor:lib"}, {"ecosystem": "npm", "package": "not-imported"}]
    observe_imports(tmp_path, inventory)
    assert [item["usage"]["status"] for item in inventory] == ["observed_import", "observed_import", "observed_import", "unknown", "not_observed"]
    assert inventory[0]["usage"]["files"] == ["main.py"]


def test_priority_explains_usage_and_exposure_without_negative_proof():
    from types import SimpleNamespace
    from app.operations import finding_priority
    vulnerability = SimpleNamespace(kev=False, cvss=7.5, epss=0.01)
    finding = SimpleNamespace(severity="HIGH", evidence={"usage": {"status": "observed_import"}, "application_exposed": True})
    assert finding_priority(finding, vulnerability)["classification"] == "Alta prioridade"
    finding.evidence["usage"]["status"] = "not_observed"
    result = finding_priority(finding, vulnerability)
    assert any("não reduz risco" in reason for reason in result["reasons"])
    vulnerability.kev = True
    assert finding_priority(finding, vulnerability)["classification"] == "Investigação imediata"
