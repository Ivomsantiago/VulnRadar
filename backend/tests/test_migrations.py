import os
import subprocess
import sys
from pathlib import Path
from sqlalchemy import create_engine, inspect


def test_upgrade_downgrade_repeatability(tmp_path):
    root = Path(__file__).resolve().parents[1]
    url = f"sqlite:///{tmp_path / 'migration.db'}"
    env = {**os.environ, "VULNRADAR_DATABASE_URL": url}

    def run(*args):
        subprocess.run([sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"), *args], cwd=root, env=env, check=True, capture_output=True)

    run("upgrade", "head")
    run("upgrade", "head")
    engine = create_engine(url)
    assert {"scans", "aliases", "watchlist", "vulnerabilities"} <= set(inspect(engine).get_table_names())
    engine.dispose()
    run("downgrade", "base")
    run("upgrade", "head")


def test_v2_upgrade_preserves_existing_records_and_scan_payload(tmp_path):
    import json
    import sqlite3

    root = Path(__file__).resolve().parents[1]
    path = tmp_path / "existing.db"
    env = {**os.environ, "VULNRADAR_DATABASE_URL": f"sqlite:///{path}"}

    def run(target):
        subprocess.run([sys.executable, "-m", "alembic", "-c", str(root / "alembic.ini"), "upgrade", target], cwd=root, env=env, check=True, capture_output=True)

    run("0002")
    payload = {"inventory": [], "findings": [], "warnings": ["Legacy coverage note"]}
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO projects (id,name,path) VALUES (1,'Existing project','/preserved')")
        connection.execute("INSERT INTO scans (id,project_id,kind,status,result,created_at) VALUES (1,1,'sca','partial',?,'2026-01-01')", (json.dumps(payload),))
        connection.execute("INSERT INTO watchlist (id,ecosystem,package,version) VALUES (1,'npm','existing','1.0.0')")
    run("head")
    with sqlite3.connect(path) as connection:
        row = connection.execute("SELECT result,status,indexed FROM scans WHERE id=1").fetchone()
        assert json.loads(row[0]) == payload and row[1] == "partial" and not row[2]
        assert connection.execute("SELECT name,path FROM projects WHERE id=1").fetchone() == ("Existing project", "/preserved")
        assert connection.execute("SELECT min_severity,alerts_enabled FROM watchlist WHERE id=1").fetchone() == ("LOW", 1)
