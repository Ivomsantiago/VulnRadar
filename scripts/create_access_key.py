"""Generate one personal 256-bit key; store only its digest in server configuration."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("name", help="Pseudonymous account ID, e.g. analyst-01")
parser.add_argument("--role", choices=["viewer", "analyst", "admin"], default="viewer")
parser.add_argument("--days", type=int, default=30)
parser.add_argument("--configure-local", action="store_true", help="Create a new local .env; refuses to replace an existing file")
args = parser.parse_args()
if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", args.name) or not 1 <= args.days <= 90:
    parser.error("Identificador inválido ou validade fora do intervalo 1-90 dias")
secret = secrets.token_urlsafe(32)
config = {args.name: {"role": args.role, "digest": hashlib.sha256(secret.encode()).hexdigest(), "expires_at": (datetime.now(timezone.utc) + timedelta(days=args.days)).isoformat()}}
if args.configure_local:
    target = Path(__file__).resolve().parents[1] / ".env"
    try:
        with target.open("x", encoding="utf-8") as stream:
            stream.write("VULNRADAR_ACCESS_MODE=local\nVULNRADAR_ACCESS_KEYS=" + json.dumps(config) + "\nVULNRADAR_OSV_QUERIES_ENABLED=false\nVULNRADAR_STORE_CODE_SNIPPETS=false\n")
    except FileExistsError:
        parser.error(".env já existe; gere sem --configure-local e mescle somente os hashes de acesso")
    target.chmod(0o600)
print("CHAVE PESSOAL (entregue por canal seguro; não inclua em Git/logs):")
print(secret)
print("CONFIGURAÇÃO (mescle com as outras contas em VULNRADAR_ACCESS_KEYS):")
print(json.dumps(config))
