from contextlib import closing
from pathlib import Path
import sqlite3
import subprocess
import sys
from app.services.backup import consistent_backup


def test_backup_and_upgrade_wrapper_preserve_v2_data(tmp_path):
    import os
    root = Path(__file__).resolve().parents[2]
    source = tmp_path / "source with spaces.db"
    env = {**os.environ, "VULNRADAR_DATABASE_URL": "sqlite:///" + source.as_posix()}
    subprocess.run([sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "0002"], cwd=root, env=env, check=True, capture_output=True)
    with closing(sqlite3.connect(source)) as connection:
        connection.execute("INSERT INTO projects (name,path) VALUES ('Preserved backup fixture','/fixture')")
        connection.commit()
    copy = tmp_path / "copy.db"
    consistent_backup(source, copy)
    with closing(sqlite3.connect(copy)) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT name FROM projects").fetchone()[0] == "Preserved backup fixture"
    subprocess.run([sys.executable, "scripts/migrate.py"], cwd=root, env=env, check=True, capture_output=True)
    backups = list((tmp_path / "backups").glob("*.db"))
    assert len(backups) == 1
    with closing(sqlite3.connect(backups[0])) as connection:
        assert connection.execute("SELECT version_num FROM alembic_version").fetchone()[0] == "0002"
    with closing(sqlite3.connect(source)) as connection:
        assert connection.execute("SELECT name FROM projects").fetchone()[0] == "Preserved backup fixture"
