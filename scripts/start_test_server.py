"""Disposable browser-test server; fixtures never enter the operational database."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=8000)
parser.add_argument("--mock-osv", action="store_true", help="Use isolated fictional OSV responses for reproducible CI only")
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix="vulnradar-v2-browser-") as temporary:
    base = Path(temporary)
    projects = base / "repositories"
    project = projects / "sample-app"
    project.mkdir(parents=True)
    (project / "package-lock.json").write_text(json.dumps({"name": "Safe browser fixture", "lockfileVersion": 3, "packages": {"": {"dependencies": {"lodash": "4.17.20"}}, "node_modules/lodash": {"version": "4.17.20"}}}))
    (project / "unsafe.py").write_text('''# Static analysis fixture. Never execute this file.
import subprocess
subprocess.run("fixture-never-executed", shell=True)
''')
    env = {**os.environ, "VULNRADAR_DATABASE_URL": f"sqlite:///{(base / 'test.db').as_posix()}", "VULNRADAR_ALLOWED_ROOTS": json.dumps([str(projects)]), "VULNRADAR_AUTO_SYNC": "false", "VULNRADAR_ORIGINS": json.dumps([f"http://127.0.0.1:{args.port}"])}
    semgrep = root / ".semgrep-venv" / ("Scripts" if os.name == "nt" else "bin")
    env["PATH"] = str(semgrep) + os.pathsep + env["PATH"]
    subprocess.run([sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "head"], cwd=root, env=env, check=True)
    entrypoint, app_dir = ("browser_test_app:app", "scripts") if args.mock_osv else ("app.main:app", "backend")
    child = subprocess.Popen([sys.executable, "-m", "uvicorn", entrypoint, "--app-dir", app_dir, "--host", "127.0.0.1", "--port", str(args.port), "--log-level", "warning", "--no-access-log"], cwd=root, env=env)
    print("Disposable browser server PID:", child.pid, "OSV:", "FICTIONAL TEST TRANSPORT" if args.mock_osv else "LIVE API", flush=True)

    def stop(*_):
        child.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        raise SystemExit(child.wait())
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=15)
