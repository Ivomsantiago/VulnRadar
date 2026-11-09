"""Run one private-team worker with native TLS and access logging disabled."""
import argparse
import os
from pathlib import Path
import sys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--certificate", type=Path, required=True)
parser.add_argument("--private-key", type=Path, required=True)
parser.add_argument("--host", default="127.0.0.1")
parser.add_argument("--port", type=int, default=8443)
args = parser.parse_args()
if not args.certificate.is_file() or not args.private_key.is_file():
    parser.error("Certificado e chave TLS precisam existir")
os.environ["VULNRADAR_ACCESS_MODE"] = "team"
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from app.config import settings  # noqa: E402
import uvicorn  # noqa: E402

if settings.access_mode != "team":
    raise SystemExit("Inicialização de equipe exige modo team")
uvicorn.run("app.main:app", host=args.host, port=args.port, ssl_certfile=str(args.certificate), ssl_keyfile=str(args.private_key), access_log=False, proxy_headers=False, workers=1)
