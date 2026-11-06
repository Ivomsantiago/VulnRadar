import asyncio
import json
import re
import shutil
import tomllib
import tempfile
import yaml
from pathlib import Path
from defusedxml.ElementTree import fromstring
from ..config import settings
from ..security import safe_files
from .intelligence import query_osv


def parse_dependencies(path: Path):
    name = path.name
    text = path.read_text(encoding="utf-8-sig")
    dependencies = []
    warnings = []

    def add(ecosystem, package, version, direct=None):
        if package and version and not any(c in version for c in "<>*^~| ${}") and not version.startswith(("file:", "git:", "workspace:", "link:")):
            dependencies.append({"ecosystem": ecosystem, "package": package, "version": version, "direct": direct})
        else:
            warnings.append(f"Versão não resolvida: {package}")

    if name == "package-lock.json":
        data = json.loads(text)
        if "packages" in data:
            direct = data["packages"].get("", {}).get("dependencies", {})
            for key, item in data["packages"].items():
                if key and item.get("version"):
                    add("npm", item.get("name") or key.rsplit("node_modules/", 1)[-1], item["version"], key.removeprefix("node_modules/") in direct)
        else:

            def walk(items, direct):
                for package, item in items.items():
                    add("npm", package, item.get("version"), direct)
                    walk(item.get("dependencies", {}), False)

            walk(data.get("dependencies", {}), True)
    elif name == "pnpm-lock.yaml":
        data = yaml.safe_load(text)
        snapshots = data.get("snapshots") or data.get("packages", {})
        if not isinstance(snapshots, dict):
            raise ValueError("Estrutura pnpm inválida")
        for key in snapshots:
            key = key.removeprefix("/").split("(", 1)[0]
            package, separator, version = key.rpartition("@")
            if not separator:
                package, separator, version = key.rpartition("/")
            add("npm", package, version)
    elif name == "yarn.lock":
        if "__metadata:" in text:
            data = yaml.safe_load(text)
            for key, item in data.items():
                if key != "__metadata" and isinstance(item, dict):
                    selector = key.split(", ")[0]
                    package = selector.rsplit("@", 1)[0]
                    add("npm", package, item.get("version"))
        else:
            selectors = None
            for line in text.splitlines():
                if line and not line[0].isspace() and not line.startswith("#") and line.endswith(":"):
                    selectors = line[:-1].strip('"').split(", ")[0].strip('"')
                elif selectors and re.match(r"^  version ", line):
                    version = line.split(None, 1)[1].strip('"')
                    add("npm", selectors.rsplit("@", 1)[0], version)
                    selectors = None
    elif name == "requirements.txt":
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^;\s]+)", line)
            if match:
                add("PyPI", match[1], match[2])
            else:
                warnings.append(f"Requisito sem versão exata: {line[:100]}")
    elif name in {"poetry.lock", "Cargo.lock"}:
        ecosystem = "PyPI" if name == "poetry.lock" else "crates.io"
        for item in tomllib.loads(text).get("package", []):
            add(ecosystem, item["name"], item["version"])
    elif name == "Pipfile.lock":
        for group in ("default", "develop"):
            for package, item in json.loads(text).get(group, {}).items():
                add("PyPI", package, item.get("version", "").removeprefix("=="))
    elif name == "composer.lock":
        data = json.loads(text)
        for item in data.get("packages", []) + data.get("packages-dev", []):
            add("Packagist", item["name"], item["version"].removeprefix("v"))
    elif name == "go.mod":
        for match in re.finditer(r"^\s*(?:require\s+)?([\w./-]+)\s+v([^\s]+)", text, re.M):
            add("Go", match[1], match[2])
    elif name == "pom.xml":
        root = fromstring(text)
        for item in root.findall(".//{*}dependencies/{*}dependency"):
            add("Maven", f"{item.findtext('{*}groupId')}:{item.findtext('{*}artifactId')}", item.findtext("{*}version"))
        warnings.append("POM não resolve propriedades, perfis, herança ou dependências transitivas")
    elif name == "gradle.lockfile":
        for line in text.splitlines():
            match = re.match(r"([^:#]+):([^:]+):([^=]+)=", line)
            if match:
                add("Maven", f"{match[1]}:{match[2]}", match[3])
    elif name == "packages.lock.json":
        for items in json.loads(text).get("dependencies", {}).values():
            for package, item in items.items():
                add("NuGet", package, item.get("resolved"), item.get("type") == "Direct")
    elif name.endswith(".cdx.json") or name == "bom.json":
        data = json.loads(text)
        if data.get("bomFormat") != "CycloneDX":
            raise ValueError("SBOM não é CycloneDX")
        ecosystems = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "crates.io", "nuget": "NuGet", "composer": "Packagist", "gem": "RubyGems"}
        for item in data.get("components", []):
            purl = item.get("purl", "")
            match = re.match(r"pkg:([^/]+)/([^@?#]+)@([^?#]+)", purl)
            if match and match[1] in ecosystems:
                from urllib.parse import unquote

                package = unquote(match[2])
                if match[1] == "maven":
                    package = package.replace("/", ":")
                add(ecosystems[match[1]], package, unquote(match[3]))
            else:
                warnings.append(f"Componente sem PURL suportado: {item.get('name', '?')}")
    return dependencies, warnings


SUPPORTED = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "poetry.lock",
    "Cargo.lock",
    "Pipfile.lock",
    "composer.lock",
    "go.mod",
    "pom.xml",
    "gradle.lockfile",
    "packages.lock.json",
    "bom.json",
}


def inventory_root(root):
    inventory, warnings = [], []
    for path in safe_files(root):
        if path.name not in SUPPORTED and not path.name.endswith(".cdx.json"):
            continue
        try:
            items, notes = parse_dependencies(path)
            for item in items:
                item["file"] = str(path.relative_to(root))
            inventory.extend(items)
            warnings.extend(notes)
        except (ValueError, KeyError, TypeError) as exc:
            warnings.append(f"Falha no parser {path.relative_to(root)}: {type(exc).__name__}")
    if not inventory:
        warnings.append("Nenhuma dependência com versão resolvida encontrada")
    return inventory, warnings


async def sca(root, progress=None):
    if progress:
        await progress("inventory")
    inventory, warnings = await asyncio.to_thread(inventory_root, root)
    findings = []
    if progress:
        await progress("advisories")
    cache = {}
    for item in inventory:
        key = (item["ecosystem"], item["package"], item["version"])
        if key not in cache:
            try:
                cache[key] = await query_osv(*key)
            except Exception as exc:
                warnings.append(f"Consulta incompleta para {item['package']}: {type(exc).__name__}")
                cache[key] = None
        item["query_status"] = "failed" if cache[key] is None else "complete"
        for advisory in cache[key] or []:
            findings.append({"dependency": item, "advisory": advisory, "evidence": "Correspondência de pacote e versão via OSV; alcançabilidade não avaliada"})
    return {"inventory": inventory, "findings": findings, "warnings": warnings, "coverage": "partial" if warnings else "complete", "engine": "OSV"}


async def sast(root, progress=None):
    if progress:
        await progress("sast")
    executable = shutil.which("semgrep")
    if not executable:
        raise ValueError("Semgrep não instalado. Instale com pip install semgrep em ambiente isolado")
    # Scan a bounded snapshot: Semgrep never traverses the original tree or symlinks.
    with tempfile.TemporaryDirectory(prefix="vulnradar-sast-") as temporary:
        snapshot = Path(temporary)
        scope = []
        for path in safe_files(root):
            relative = path.relative_to(root)
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            # Refuse symlinks even if the original entry changes during enumeration.
            import os

            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as handle:
                content = handle.read(settings.max_file_bytes + 1)
            if len(content) > settings.max_file_bytes:
                raise ValueError("Arquivo excede o limite")
            target.write_bytes(content)
            scope.append(relative.as_posix())
        process = await asyncio.create_subprocess_exec(
            executable,
            "scan",
            "--config",
            str(settings.semgrep_rules),
            "--json",
            "--metrics=off",
            "--disable-version-check",
            "--no-git-ignore",
            "--max-target-bytes",
            str(settings.max_file_bytes),
            "--jobs",
            "1",
            ".",
            cwd=snapshot,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        async def bounded_read(stream, maximum):
            output = bytearray()
            while chunk := await stream.read(65536):
                output.extend(chunk)
                if len(output) > maximum:
                    raise ValueError("Saída do mecanismo excede o limite de recursos")
            return bytes(output)

        output_tasks = [
            asyncio.create_task(bounded_read(process.stdout, settings.max_file_bytes * 2)),
            asyncio.create_task(bounded_read(process.stderr, 1_000_000)),
            asyncio.create_task(process.wait()),
        ]
        try:
            stdout, stderr, _ = await asyncio.wait_for(asyncio.gather(*output_tasks), timeout=settings.scan_timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError, ValueError):
            if process.returncode is None:
                process.kill()
            await process.wait()
            for task in output_tasks:
                task.cancel()
            await asyncio.gather(*output_tasks, return_exceptions=True)
            raise
        if process.returncode != 0:
            raise ValueError(f"Semgrep terminou com código {process.returncode}")
        data = json.loads(stdout)
        local_rules = []
        for rule_file in sorted(settings.semgrep_rules.glob("*.y*ml")):
            local_rules.extend(rule.get("id") for rule in yaml.safe_load(rule_file.read_text()).get("rules", []) if rule.get("id"))
        for finding in data.get("results", []):
            original = finding.get("check_id", "")
            local = next((name for name in sorted(local_rules, key=len, reverse=True) if original == name or original.endswith("." + name)), original)
            finding["original_check_id"], finding["check_id"] = original, local
            relative = finding.get("path", "")
            source = (snapshot / relative).resolve()
            if source.is_relative_to(snapshot) and source.is_file():
                lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
                start = max(0, finding.get("start", {}).get("line", 1) - 2)
                end = min(len(lines), finding.get("end", {}).get("line", start + 1) + 1)
                snippet = "\n".join(f"{index + 1}: {lines[index]}" for index in range(start, min(end, start + 12)))
                snippet = re.sub(r"(?i)((?:password|secret|api[_-]?key|token)\s*=\s*)[\"'][^\"']+[\"']", r"\1'<redacted>'", snippet)
                snippet = re.sub(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})", "<redacted>", snippet)
                finding.setdefault("extra", {})["lines"] = snippet[:6000]
    import hashlib

    rules_digest = hashlib.sha256(b"".join(rule.read_bytes() for rule in sorted(settings.semgrep_rules.glob("*.y*ml")))).hexdigest()
    return {
        "scope": sorted(scope),
        "rules_digest": rules_digest,
        "findings": data.get("results", []),
        "warnings": data.get("errors", []),
        "coverage": "partial" if data.get("errors") else "rules-only",
        "engine": "Semgrep; somente regras locais, sem prova de explorabilidade",
    }
