"""Consistent SQLite backup; never copy an active WAL database directly."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.services.backup import consistent_backup  # noqa: E402

parser = argparse.ArgumentParser(description="Backup consistente SQLite VulnRadar")
parser.add_argument("source", type=Path)
parser.add_argument("destination", type=Path)
args = parser.parse_args()
if not args.source.is_file() or args.destination.exists():
    parser.error("Origem deve existir e destino deve ser novo")
consistent_backup(args.source, args.destination)
print("Backup criado e integridade verificada")
