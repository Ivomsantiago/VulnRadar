"""Generate a source/schema inventory without connecting to operational data."""
import ast
from contextlib import closing
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
output = root / "docs" / "review" / "v4"
output.mkdir(parents=True, exist_ok=True)
modules, routes, large_functions = [], [], []
policy_tree = ast.parse((root / "backend/app/access.py").read_text(encoding="utf-8"))
policies = {node.targets[0].id: ast.literal_eval(node.value) for node in policy_tree.body
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id in {"READ_ROUTES", "ANALYST_READ", "ANALYST_WRITE"}}
prefixes = {"backend/app/access.py": "/api/auth", "backend/app/imports.py": "/api",
            "backend/app/operations.py": "/api", "backend/app/reports.py": "/api",
            "backend/app/services/products.py": "/api", "backend/app/services/oci.py": "/api"}
public_paths = {"/health", "/ready", "/api/health", "/api/ready", "/api/auth/session", "/api/auth/login"}
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
                        route = prefixes.get(name, "") + ast.literal_eval(decorator.args[0])
                        method = decorator.func.attr.upper()
                        example = re.sub(r"\{[^}]+\}", "1", route)
                        public = route in public_paths or not route.startswith("/api/")
                        permissions = {}
                        for role in ("viewer", "analyst", "admin"):
                            patterns = policies["READ_ROUTES"] + (policies["ANALYST_READ"] if role == "analyst" else ()) if method == "GET" else policies["ANALYST_WRITE"] if role == "analyst" else ()
                            permissions[role] = public or route == "/api/auth/logout" or role == "admin" or any(re.fullmatch(pattern, example) for pattern in patterns)
                        routes.append({"path": name, "line": node.lineno, "method": method, "route": route, "public": public, "roles": permissions})
with tempfile.TemporaryDirectory(prefix="vulnradar-v4-schema-") as temporary:
    env = {**os.environ, "VULNRADAR_DATABASE_URL": "sqlite:///" + (Path(temporary) / "schema.db").as_posix()}
    subprocess.run([sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "upgrade", "head"], cwd=root, env=env, check=True)
    result = subprocess.run([sys.executable, "-m", "alembic", "-c", "backend/alembic.ini", "check"], cwd=root, env=env, capture_output=True, text=True)
    import sqlite3
    with closing(sqlite3.connect(Path(temporary) / "schema.db")) as connection:
        schema = "\n".join(row[0] + ";" for row in connection.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name"))
        queries = ["SELECT id FROM vulnerabilities WHERE severity='HIGH' ORDER BY published DESC,id DESC LIMIT 25", "SELECT id FROM vulnerabilities WHERE kev=1 ORDER BY published DESC,id DESC LIMIT 25"]
        plans = [{"query": query, "plan": list(connection.execute("EXPLAIN QUERY PLAN " + query))} for query in queries]
    (output / "schema.sql").write_text("\n".join(line.rstrip() for line in schema.splitlines()) + "\n", encoding="utf-8")
    (output / "alembic-check.txt").write_text(result.stdout + result.stderr, encoding="utf-8")
    (output / "query-plans.json").write_text(json.dumps(plans, indent=2), encoding="utf-8")
inventory = {"scope": "Source and newly migrated disposable database; no operational data", "modules": modules, "routes": routes, "large_functions": large_functions, "dependencies": {"python": (root / "backend/requirements.txt").read_text().splitlines(), "frontend": json.loads((root / "frontend/package.json").read_text())}, "migrations": [p.name for p in sorted((root / "backend/alembic/versions").glob("*.py"))]}
inventory["modules_over_400_lines"] = [item for item in modules if item["lines"] > 400]
inventory["tree"] = sorted(path.relative_to(root).as_posix() for base in ("backend/app", "backend/alembic/versions", "frontend/src", "scripts") for path in (root / base).rglob("*") if path.is_file() and "__pycache__" not in path.parts)
(output / "inventory.json").write_text(json.dumps(inventory, indent=2, ensure_ascii=False), encoding="utf-8")
(output / "api-inventory.json").write_text(json.dumps({"scope": "Declared routes and static role policy; protected routes require authentication. Domain security review is not exhaustive.", "boundary_regressions": "backend/tests/test_access_v4.py", "routes": routes}, indent=2), encoding="utf-8")
print(f"{len(modules)} modules; {len(routes)} route declarations; {len(large_functions)} functions over 60 lines; alembic check exit={result.returncode}")
