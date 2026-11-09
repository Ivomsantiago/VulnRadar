"""Upgrade the configured database, creating a consistent pre-upgrade backup."""
from pathlib import Path
import sys
from alembic.config import Config

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "backend"))
from app.migration_runner import migrate  # noqa: E402

migrate(Config(str(root / "backend/alembic.ini")))
