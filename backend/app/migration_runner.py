"""Official SQLite migration path: back up an existing database before upgrade."""
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.engine import make_url
from .config import settings
from .services.backup import consistent_backup


def migrate(config):
    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite":
        raise ValueError("Migrador oficial suporta SQLite; PostgreSQL permanece experimental e não validado")
    database = url.database
    if database and database != ":memory:":
        source = Path(database).resolve()
        head = ScriptDirectory.from_config(config).get_current_head()
        current = None
        if source.is_file():
            with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as connection:
                try:
                    current = connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
                except (sqlite3.OperationalError, TypeError):
                    current = None
            if current != head:
                directory = source.parent / "backups"
                directory.mkdir(parents=True, exist_ok=True)
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
                consistent_backup(source, directory / (source.stem + "-" + timestamp + ".db"))
    command.upgrade(config, "head")


if __name__ == "__main__":
    migrate(Config(str(Path(__file__).resolve().parents[1] / "alembic.ini")))
