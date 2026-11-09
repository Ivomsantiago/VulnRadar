"""Generate a source/schema inventory without connecting to operational data."""
import ast
from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
output = root / "docs" / "review" / "v4"
output.mkdir(parents=True, exist_ok=True)
modules, routes, large_functions = [], [], []
for base in ("backend/app", "frontend/src", "scripts"):
    for path in sorted((root / base).rglob("*")):
        if path.suffix not in {".py", ".ts", ".tsx", ".css"}:
            continue
        text = path.read_text(encoding="utf-8-sig")
        name = path.relative_to(root).as_posix()
        modules.append({"path": name, "lines": len(text.splitlines())})
        if path.suffix != ".py":
            continue
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                length = node.end_lineno - node.lineno + 1
                if length > 60:
                    large_functions.append({"path": name, "line": node.lineno, "function": node.name, "lines": length})
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr in {"get", "post", "patch", "put", "delete"}:
                        routes.append({"path": name, "line": node.lineno, "method": decorator.func.attr.upper(), "route": ast.literal_eval(decorator.args[0])})
with tempfile.TemporaryDirectory(prefix="vulnradar-v4-schema-") as temporary:
    env = {**os.environ, "VULNRADAR_DATABASE_URL": "sqlite:///" + (Path(temporary) / "schema.db").as_posix()}
    subprocess.run([sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "head"], cwd=root, env=env, check=True)
    result = subprocess.run([sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "check"], cwd=root, env=env, capture_output=True, text=True)
    import sqlite3
    with closing(sqlite3.connect(Path(temporary) / "schema.db")) as connection:
        schema = "\n".join(row[0] + ";" for row in connection.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name"))
    (output / "schema.sql").write_text(schema, encoding="utf-8")
    (output / "alembic-check.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
inventory = {"scope": "Source and newly migrated disposable database; no operational data", "modules": modules, "routes": routes, "large_functions": large_functions, "dependencies": {"python": (root / "backend/requirements.txt").read_text().splitlines(), "frontend": json.loads((root / "frontend/package.json").read_text())}, "migrations": [p.name for p in sorted((root / "backend/alembic/versions").glob("*.py"))]}
(output / "inventory.json").write_text(json.dumps(inventory, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"{len(modules)} modules; {len(routes)} route declarations; {len(large_functions)} functions over 60 lines; alembic check exit={result.returncode}")
