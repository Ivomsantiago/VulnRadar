import os
from pathlib import Path
import pytest
from app.services.scanner import sast


@pytest.mark.asyncio
async def test_real_semgrep_local_rules(tmp_path, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "store_code_snippets", True)
    tool = Path(__file__).resolve().parents[2] / ".semgrep-venv" / ("Scripts" if os.name == "nt" else "bin")
    if not (tool / ("semgrep.exe" if os.name == "nt" else "semgrep")).exists():
        pytest.skip("Semgrep separado não instalado")
    monkeypatch.setenv("PATH", str(tool) + os.pathsep + os.environ["PATH"])
    (tmp_path / "unsafe.py").write_text('import subprocess\napi_key = "TEST_ONLY_SECRET"\nsubprocess.run("echo fixture", shell=True)\n')
    result = await sast(tmp_path)
    assert any("python-subprocess-shell" in item["check_id"] for item in result["findings"])
    assert all(not item["path"].startswith(str(tmp_path)) for item in result["findings"])

    finding = next(item for item in result["findings"] if "python-subprocess-shell" in item["check_id"])
    assert finding["check_id"] == "python-subprocess-shell"
    assert "subprocess.run" in finding["extra"]["lines"]
    assert "TEST_ONLY_SECRET" not in finding["extra"]["lines"]
    original = finding["code_digest"]
    source = tmp_path / "unsafe.py"
    source.write_text("\n\n\n" + source.read_text())
    moved = await sast(tmp_path)
    shifted = next(item for item in moved["findings"] if item["check_id"] == finding["check_id"])
    assert shifted["code_digest"] == original
    assert shifted["start"]["line"] == finding["start"]["line"] + 3
    # A repository cannot make an existing issue look fixed using ignore controls.
    (tmp_path / ".semgrepignore").write_text("*.py\n")
    source.write_text(source.read_text().replace('shell=True)', 'shell=True)  # nosemgrep'))
    ignored = await sast(tmp_path)
    assert any(item["check_id"] == finding["check_id"] for item in ignored["findings"])
    assert ignored["engine_version"]
    monkeypatch.setattr(settings, "store_code_snippets", False)
    minimal = await sast(tmp_path)
    assert all("lines" not in item.get("extra", {}) and "metavars" not in item.get("extra", {}) for item in minimal["findings"])
    assert all(item.get("code_digest") for item in minimal["findings"])
