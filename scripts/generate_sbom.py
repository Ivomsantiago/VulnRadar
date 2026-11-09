"""Generate the application's CycloneDX inventory from pinned Python/npm manifests."""
import json
from pathlib import Path
from urllib.parse import quote

root = Path(__file__).resolve().parents[1]
components = {}
for line in (root / "backend/requirements.txt").read_text().splitlines():
    if "==" not in line:
        continue
    name, version = line.split(";", 1)[0].strip().split("==", 1)
    purl = f"pkg:pypi/{quote(name.lower().replace('_', '-'), safe='')}@{quote(version, safe='')}"
    components[purl] = {"type": "library", "name": name, "version": version, "purl": purl}
lock = json.loads((root / "frontend/package-lock.json").read_text(encoding="utf-8"))
for path, item in lock.get("packages", {}).items():
    if not path or not item.get("version"):
        continue
    name = item.get("name") or path.rsplit("node_modules/", 1)[-1]
    purl = f"pkg:npm/{quote(name, safe='/')}@{quote(item['version'], safe='')}"
    components[purl] = {"type": "library", "name": name, "version": item["version"], "purl": purl, "properties": [{"name": "vulnradar:build-only", "value": str(bool(item.get("dev"))).lower()}]}
document = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {"component": {"type": "application", "name": "VulnRadar", "version": lock["version"]}},
            "components": [components[key] for key in sorted(components)]}
target = root / "docs/review/v4/vulnradar.cdx.json"
target.parent.mkdir(parents=True, exist_ok=True)
target.write_text(json.dumps(document, indent=2), encoding="utf-8")
print(f"{len(components)} declared components; output={target.relative_to(root)}; does not include OS/base images or optional Semgrep environment")
