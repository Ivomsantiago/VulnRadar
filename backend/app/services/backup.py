"""Consistent SQLite backups without copying live WAL files."""
from contextlib import closing
from pathlib import Path
import sqlite3


def consistent_backup(source: Path, destination: Path) -> None:
    source, destination = source.resolve(strict=True), destination.resolve()
    if not source.is_file() or destination.exists() or source == destination:
        raise ValueError("Origem deve existir e destino deve ser novo")
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as connection:
        with closing(sqlite3.connect(destination)) as target:
            connection.backup(target)
            if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Integridade do backup não confirmada")
    destination.chmod(0o600)
