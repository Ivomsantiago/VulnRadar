"""Import observation is a heuristic, never proof of vulnerability reachability."""
import ast
from collections import defaultdict
import re
from ..security import read_file, safe_files


def observe_imports(root, inventory):
    root = root.resolve(strict=True)
    observed = defaultdict(list)
    inspected, incomplete = set(), set()
    try:
        for path in safe_files(root):
            ecosystem = "PyPI" if path.suffix == ".py" else "npm" if path.suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"} else None
            if ecosystem is None:
                continue
            inspected.add(ecosystem)
            try:
                text = read_file(root, path).decode("utf-8-sig")
                if ecosystem == "PyPI":
                    imports = []
                    for node in ast.walk(ast.parse(text)):
                        if isinstance(node, ast.Import):
                            imports.extend(alias.name.split(".")[0] for alias in node.names)
                        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                            imports.append(node.module.split(".")[0])
                else:
                    imports = re.findall(r'''(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["']([^"']+)["']''', text)
                for name in imports:
                    if ecosystem == "npm":
                        name = "/".join(name.split("/")[:2]) if name.startswith("@") else name.split("/")[0]
                    else:
                        name = name.replace("_", "-").lower()
                    if len(observed[(ecosystem, name)]) < 10:
                        observed[(ecosystem, name)].append(path.relative_to(root).as_posix())
            except (OSError, ValueError, SyntaxError, UnicodeError):
                incomplete.add(ecosystem)
    except (OSError, ValueError):
        incomplete.update({"npm", "PyPI"})
    for item in inventory:
        name = item["package"].replace("_", "-").lower() if item["ecosystem"] == "PyPI" else item["package"]
        files = sorted(set(observed.get((item["ecosystem"], name), [])))
        item["usage"] = {"status": "observed_import" if files else "unknown" if item["ecosystem"] not in inspected or item["ecosystem"] in incomplete else "not_observed", "files": files,
                         "method": "Heurística de imports estáticos JS/TS/Python; nomes de distribuição e módulo podem diferir. Ausência não prova código inalcançável."}
