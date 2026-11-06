"""Consistent SQLite backup; never copy an active WAL database directly."""
import argparse
import sqlite3
from pathlib import Path

parser = argparse.ArgumentParser(description="Backup consistente SQLite VulnRadar")
parser.add_argument("source", type=Path)
parser.add_argument("destination", type=Path)
args = parser.parse_args()
if not args.source.is_file() or args.destination.exists():
    parser.error("Origem deve existir e destino deve ser novo")
with sqlite3.connect(f"file:{args.source.resolve().as_posix()}?mode=ro", uri=True) as source:
    with sqlite3.connect(args.destination) as destination:
        source.backup(destination)
        result = destination.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise RuntimeError("Backup inválido")
print("Backup criado e integridade verificada")
