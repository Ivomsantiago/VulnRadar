from copy import deepcopy
import pytest
from sqlalchemy import select, func
from app.db import Finding, FindingObservation, Project
from app.services.sarif_import import import_sarif, normalize_sarif, validator
from app.services.reporting import sarif


def document():
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL", "version": "test-only"}}, "results": [{"ruleId": "py/example", "level": "error", "message": {"text": "Fixture finding; no external scan was run"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/server.py"}, "region": {"startLine": 4}}}]}]}]}


def test_export_matches_official_schema_and_import_deduplicates_without_closing(session):
    raw = document()
    project = Project(name="SARIF test", path="/fixture")
    session.add(project)
    session.commit()
    first = import_sarif(session, project.id, raw)
    finding = session.scalar(select(Finding))
    finding.status = "false_positive"
    session.commit()
    changed = deepcopy(raw)
    changed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] = 12
    second = import_sarif(session, project.id, changed)
    assert first.status == second.status == "partial"
    assert session.scalar(select(func.count()).select_from(Finding)) == 1
    assert session.scalar(select(func.count()).select_from(FindingObservation)) == 2
    assert finding.status == "false_positive" and finding.line == 12
    assert validator().is_valid(sarif(second.result["findings"]))
    import_sarif(session, project.id, {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}]})
    assert finding.status == "false_positive"


@pytest.mark.parametrize("uri", ["../../secret", "https://metadata.google.internal/file", "file://remote/share/file", "javascript:alert(1)"])
def test_import_rejects_remote_uris_and_traversal(uri):
    raw = document()
    raw["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = uri
    with pytest.raises(ValueError):
        normalize_sarif(raw)


def test_invalid_schema_and_result_limit_are_rejected():
    with pytest.raises(ValueError):
        normalize_sarif({"version": "1.0", "runs": []})
    raw = document()
    raw["runs"][0]["results"] *= 2001
    with pytest.raises(ValueError, match="2000"):
        normalize_sarif(raw)


def test_application_sbom_and_inventory_export_match_official_schema():
    import json
    from pathlib import Path
    from app.services.reporting import cyclone_dx
    from app.services.schema_validation import cyclonedx_validator
    assert cyclonedx_validator().is_valid(cyclone_dx([{"ecosystem": "npm", "package": "@scope/package", "version": "1.2.3"}]))
    path = Path(__file__).resolve().parents[2] / "docs/review/v4/vulnradar.cdx.json"
    if path.exists():
        assert cyclonedx_validator().is_valid(json.loads(path.read_text()))
