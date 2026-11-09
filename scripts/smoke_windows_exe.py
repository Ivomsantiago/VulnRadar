"""Smoke a local Windows build with a disposable DB/account and no browser launch."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPCookieProcessor
import http.cookiejar

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("executable", type=Path)
args = parser.parse_args()
executable = args.executable.resolve(strict=True)
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 8000))
with tempfile.TemporaryDirectory(prefix="vulnradar-v4-exe-") as temporary:
    base = Path(temporary)
    key = secrets.token_urlsafe(32)
    env = {**os.environ, "LOCALAPPDATA": str(base), "VULNRADAR_NO_BROWSER": "1",
           "VULNRADAR_DATABASE_URL": "sqlite:///" + (base / "smoke.db").as_posix(),
           "VULNRADAR_ACCESS_MODE": "local", "VULNRADAR_AUTO_SYNC": "false", "VULNRADAR_ALLOWED_ROOTS": "[]",
           "VULNRADAR_ALLOWED_HOSTS": '["127.0.0.1"]', "VULNRADAR_ORIGINS": '["http://127.0.0.1:8000"]',
           "VULNRADAR_OSV_QUERIES_ENABLED": "false",
           "VULNRADAR_ACCESS_KEYS": json.dumps({"smoke-admin": {"role": "admin", "digest": hashlib.sha256(key.encode()).hexdigest(), "expires_at": "2099-01-01T00:00:00Z"}})}
    with (base / "launcher.log").open("w") as log:
        child = subprocess.Popen([str(executable)], cwd=base, env=env, stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def request(path, document=None):
            data = json.dumps(document).encode() if document is not None else None
            req = Request("http://127.0.0.1:8000" + path, data=data, headers={"Content-Type": "application/json", "X-VulnRadar-Client": "web"})
            try:
                with opener.open(req, timeout=2) as response:
                    return response.status, response.read()
            except HTTPError as exc:
                return exc.code, exc.read()

        try:
            for _ in range(60):
                if child.poll() is not None:
                    raise RuntimeError("Executable exited before healthcheck; inspect local build")
                try:
                    if request("/api/health")[0] == 200:
                        break
                except (URLError, OSError):
                    pass
                time.sleep(0.25)
            health = request("/api/health")[0]
            denied = request("/api/projects")[0]
            login = request("/api/auth/login", {"access_key": key})[0]
            projects, body = request("/api/projects")
            ready = request("/api/ready")[0]
            frontend = request("/")[0]
            assert (health, denied, login, projects, ready, frontend) == (200, 401, 200, 200, 200, 200)
            assert json.loads(body) == []
            result = {"build": "PyInstaller 6.22.3 Windows onedir", "binary_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                      "database": "disposable outside checkout", "health": health, "unauthenticated_projects": denied,
                      "login": login, "authenticated_projects": projects, "ready": ready, "frontend": frontend,
                      "interactive_browser": "not exercised; launch suppressed"}
            target = Path(__file__).resolve().parents[1] / "docs/review/v4/windows-exe-smoke.json"
            target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
            print("Executable smoke passed: health/login/ready/frontend=200, protected API=401, workspace empty")
        finally:
            child.terminate()
            child.wait(timeout=15)
