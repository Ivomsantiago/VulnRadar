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
