import json
from pathlib import Path

import pytest

from app.config import settings
from app.schemas import SarifInput
from app.services.scanner import inventory_root, parse_dependencies


def test_import_rejects_excessive_depth_before_schema_validation():
    nested = {}
    for _ in range(40):
        nested = {"nested": nested}
    with pytest.raises(ValueError):
        SarifInput(document=nested)


def test_yaml_alias_expansion_is_rejected_and_scan_stays_partial(tmp_path):
    # Small graph fixture, never a large DoS payload.
    text = "base: &base {version: 1.0.0}\nmerged: {<<: *base}\npackages: {lib@1.0.0: {}}\n"
    path = tmp_path / "pnpm-lock.yaml"
    path.write_text(text)
    with pytest.raises(ValueError):
        parse_dependencies(path)
    items, warnings = inventory_root(tmp_path)
    assert not items and warnings


def test_component_budget_is_applied_inside_parser(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "max_components", 2)
    content = json.dumps({"packages": {f"node_modules/lib-{index}": {"version": "1.0.0"} for index in range(4)}}).encode()
    with pytest.raises(ValueError):
        parse_dependencies(Path("package-lock.json"), content)
    (tmp_path / "package-lock.json").write_bytes(content)
    items, warnings = inventory_root(tmp_path)
    assert len(items) == 2 and warnings


def test_pip_index_credentials_never_appear_in_scan_warnings(tmp_path):
    (tmp_path / "requirements.txt").write_text("--extra-index-url https://fixture:FIXTURE_INDEX_CREDENTIAL@packages.example.test/simple\n--token FIXTURE_OTHER_CREDENTIAL\n")
    _, warnings = inventory_root(tmp_path)
    assert warnings
    assert "FIXTURE_INDEX_CREDENTIAL" not in json.dumps(warnings)
    assert "FIXTURE_OTHER_CREDENTIAL" not in json.dumps(warnings)


def test_browser_fixture_disables_inherited_notification_destinations():
    import os
    import subprocess
    import sys
    root = Path(__file__).resolve().parents[2]
    code = "import sys; sys.path.insert(0, 'scripts'); import browser_test_app; from app.config import settings; assert settings.webhook_url is None and settings.smtp_host is None; assert settings.nvd_api_key is None and settings.github_token is None"
    env = {**os.environ, "VULNRADAR_DATABASE_URL": "sqlite:///:memory:", "VULNRADAR_NOTIFICATION_CHANNEL": "webhook",
           "VULNRADAR_WEBHOOK_URL": "https://fixture-never-contacted.example.test",
           "VULNRADAR_SMTP_HOST": "fixture-never-contacted.example.test",
           "VULNRADAR_NVD_API_KEY": "FIXTURE_SOURCE_CREDENTIAL", "VULNRADAR_GITHUB_TOKEN": "FIXTURE_SOURCE_CREDENTIAL"}
    subprocess.run([sys.executable, "-c", code], cwd=root, env=env, check=True, capture_output=True, timeout=15)


@pytest.mark.parametrize("filename,content", [("package-lock.json", "[]"), ("package-lock.json", '{"packages":{"node_modules/bad":null}}'), ("pnpm-lock.yaml", "- invalid\n- root\n")])
def test_malformed_manifest_preserves_other_observed_components(tmp_path, filename, content):
    (tmp_path / filename).write_text(content)
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n")
    items, warnings = inventory_root(tmp_path)
    assert items[0]["package"] == "requests"
    assert warnings
