import os
from pathlib import Path
import pytest
from app.services.scanner import sast


@pytest.mark.asyncio
async def test_real_semgrep_local_rules(tmp_path, monkeypatch):
    tool = Path(__file__).resolve().parents[2] / ".semgrep-venv" / "bin"
    if not (tool / "semgrep").exists():
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
