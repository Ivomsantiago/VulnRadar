"""Launcher for a Windows PyInstaller build; data stays outside _MEIPASS."""
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path


def main():
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[1]))
    data = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share")) / "VulnRadar"
    data.mkdir(parents=True, exist_ok=True)
    os.chdir(data)
    os.environ.setdefault("VULNRADAR_DATABASE_URL", f"sqlite:///{(data / 'vulnradar.db').as_posix()}")
    os.environ.setdefault("VULNRADAR_FRONTEND_DIST", str(base / "frontend" / "dist"))
    os.environ.setdefault("VULNRADAR_SEMGREP_RULES", str(base / "rules" / "semgrep"))
    sys.path.insert(0, str(base / "backend"))
    from alembic.config import Config
    from app.migration_runner import migrate
    config = Config(str(base / "backend" / "alembic.ini"))
    migrate(config)
    def browser():
        import urllib.request
        for _ in range(50):
            try:
                with urllib.request.urlopen("http://127.0.0.1:8000/api/health", timeout=1) as response:
                    if response.status == 200:
                        webbrowser.open("http://127.0.0.1:8000")
                        return
            except OSError:
                time.sleep(0.2)
    if os.environ.get("VULNRADAR_NO_BROWSER") != "1":
        threading.Thread(target=browser, daemon=True).start()
    import uvicorn
    from app.main import app
    uvicorn.run(app, host="127.0.0.1", port=8000, access_log=False)


if __name__ == "__main__":
    main()
