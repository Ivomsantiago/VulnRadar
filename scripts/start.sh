#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -x .semgrep-venv/bin/semgrep ]]; then export PATH="$PWD/.semgrep-venv/bin:$PATH"; fi
exec .venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --no-access-log
