"""Functional SAST/API validation with temporary database and fixture only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import httpx

root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="vulnradar-smoke-") as temporary:
    base = Path(temporary)
    project = base / "fixture"
    project.mkdir()
    (project / "unsafe.py").write_text('import subprocess\nsubprocess.run("fixture never executed", shell=True)\n')
    env = {**os.environ, "VULNRADAR_DATABASE_URL": f"sqlite:///{(base / 'smoke.db').as_posix()}", "VULNRADAR_ALLOWED_ROOTS": json.dumps([str(project)]), "VULNRADAR_AUTO_SYNC": "false"}
    tool = root / ".semgrep-venv" / ("Scripts" if os.name == "nt" else "bin")
    env["PATH"] = str(tool) + os.pathsep + env["PATH"]
    subprocess.run([sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "head"], cwd=root, env=env, check=True)
    server = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--app-dir", "backend", "--host", "127.0.0.1", "--port", "8001"], cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        with httpx.Client(base_url="http://127.0.0.1:8001", headers={"X-VulnRadar-Client": "web"}, timeout=10, trust_env=False) as client:
            for attempt in range(50):
                try:
                    response = client.get("/api/health")
                    response.raise_for_status()
                    break
                except httpx.HTTPError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Backend não iniciou")
            response = client.post("/api/projects", json={"name": "Temporary smoke fixture", "path": str(project)})
            response.raise_for_status()
            project_id = response.json()["id"]
            response = client.post(f"/api/projects/{project_id}/scans/sast")
            response.raise_for_status()
            scan_id = response.json()["id"]
            for attempt in range(100):
                rows = client.get("/api/scans").json()
                scan = next(row for row in rows if row["id"] == scan_id)
                if scan["status"] not in {"pending", "running"}:
                    break
                time.sleep(0.1)
            assert scan["status"] == "completed", scan
            assert any("python-subprocess-shell" in finding["check_id"] for finding in scan["result"]["findings"])
            report = client.get(f"/api/scans/{scan_id}/export?format=sarif")
            report.raise_for_status()
            assert report.json()["runs"][0]["results"]
            assert client.get("/api/activity").json()
            print("PASS: cadastro autorizado, job SAST real, achado persistido, histórico e exportação SARIF")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
