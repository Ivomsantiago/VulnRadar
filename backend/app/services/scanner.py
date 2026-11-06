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
from ..security import safe_files, read_file
from .intelligence import query_osv, query_osv_batch
from .packages import package_identity


def parse_dependencies(path: Path, content=None):
    name = path.name
    content = read_file(path.parent, path) if content is None else content
    text = content.decode("utf-8-sig")
    dependencies = []
    warnings = []
    yarn_selectors = {}

    def add(ecosystem, package, version, direct=None):
        version = str(version) if version is not None else ""
        valid = bool(package and version) and not any(c in version for c in "<>*^~| ${}[](),") and version.lower() not in {"latest", "release"}
        if ecosystem in {"npm", "Go", "crates.io"}:
            valid = valid and bool(re.fullmatch(r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version))
        if ecosystem == "PyPI":
            from packaging.version import Version, InvalidVersion
            try:
                Version(version)
            except InvalidVersion:
                valid = False
            package = re.sub(r"[-_.]+", "-", str(package)).lower()
        if ecosystem == "Packagist" and version.startswith("dev-"):
            valid = False
        if ecosystem == "Maven" and version.endswith("-SNAPSHOT"):
            valid = False
        if ecosystem == "Maven" and "+" in version:
            valid = False
        if ecosystem == "NuGet":
            valid = valid and bool(re.fullmatch(r"\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version))
        if valid and not version.startswith(("file:", "git:", "workspace:", "link:", "http:", "https:")):
            dependencies.append({"ecosystem": ecosystem, "package": package_identity(ecosystem, package), "version": version, "direct": direct})
        else:
            warnings.append(f"Versão não resolvida: {package}")

    if name == "package-lock.json":
        data = json.loads(text)
        if "packages" in data:
            root_package = data["packages"].get("", {})
            direct = {**root_package.get("dependencies", {}), **root_package.get("devDependencies", {}), **root_package.get("optionalDependencies", {})}
            for key, item in data["packages"].items():
                if key and item.get("version"):
                    add(
                        "npm",
                        item.get("name") or key.rsplit("node_modules/", 1)[-1],
                        item["version"],
                        key == "node_modules/" + (item.get("name") or key.rsplit("node_modules/", 1)[-1]) and key.removeprefix("node_modules/") in direct,
                    )
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
        direct_refs = set()
        importers = data.get("importers", {".": data})
        for importer in importers.values():
            for group in ("dependencies", "devDependencies", "optionalDependencies"):
                for dependency, value in importer.get(group, {}).items():
                    resolved = value.get("version", "") if isinstance(value, dict) else value
                    direct_refs.add((dependency, str(resolved).split("(", 1)[0].split("_", 1)[0]))
        for key in snapshots:
            key = key.removeprefix("/").split("(", 1)[0]
            match = re.match(r"^(@[^/]+/[^/@]+|[^/@]+)@(.+)$", key) or re.match(r"^(@[^/]+/[^/]+|[^/]+)/(.+)$", key)
            if match:
                package, version = match[1], match[2].split("_", 1)[0]
                add("npm", package, version, (package, version) in direct_refs if direct_refs else None)
            else:
                warnings.append("Chave pnpm sem coordenadas resolvidas")
    elif name == "yarn.lock":
        if "__metadata:" in text:
            data = yaml.safe_load(text)
            for key, item in data.items():
                if key != "__metadata" and isinstance(item, dict):
                    selector = item.get("resolution", key.split(", ")[0])
                    package = selector.split("@npm:", 1)[0] if "@npm:" in selector else selector.rsplit("@", 1)[0]
                    if "@workspace:" in selector or "@patch:" in selector:
                        warnings.append("Entrada Yarn workspace/patch sem versão de registro comprovada")
                        continue
                    add("npm", package, item.get("version"))
                    yarn_selectors[(package, item.get("version"))] = set(key.split(", "))
        else:
            selectors = None
            for line in text.splitlines():
                if line and not line[0].isspace() and not line.startswith("#") and line.endswith(":"):
                    import csv
                    selectors = next(csv.reader([line[:-1]], skipinitialspace=True))
                elif selectors and re.match(r"^  version ", line):
                    version = line.split(None, 1)[1].strip('"')
                    selector = selectors[0]
                    package = selector.split("@npm:", 1)[-1].rsplit("@", 1)[0] if "@npm:" in selector else selector.rsplit("@", 1)[0]
                    add("npm", package, version)
                    yarn_selectors[(package, version)] = set(selectors)
                    selectors = None
    elif name == "requirements.txt":
        for line in text.replace("\\\n", " ").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?==([^;\s]+)", line)
            if match:
                if ";" in line:
                    warnings.append("Marcador de ambiente Python não avaliado; presença depende do ambiente alvo")
                add("PyPI", match[1], match[2])
            else:
                warnings.append(f"Requisito sem versão exata: {line[:100]}")
    elif name in {"poetry.lock", "Cargo.lock", "uv.lock"}:
        ecosystem = "crates.io" if name == "Cargo.lock" else "PyPI"
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
        replacements = {}
        for old, old_version, new, new_version in re.findall(r"(?:replace\s+)?([\w./-]+)(?:\s+(v[^\s]+))?\s*=>\s*([\w./-]+)(?:\s+(v[^\s]+))?", text):
            replacements[(old, old_version)] = (new, new_version)
        for match in re.finditer(r"^\s*(?:require\s+)?([\w./-]+)\s+v([^\s]+)", text, re.M):
            line = text[match.start():].splitlines()[0]
            if "=>" in line:
                continue
            replacement = replacements.get((match[1], "v" + match[2])) or replacements.get((match[1], ""))
            if replacement and not replacement[1]:
                warnings.append("Replace Go local sem versão de registro; dependência não consultada")
                continue
            package, version = replacement if replacement else (match[1], match[2])
            add("Go", package, version.removeprefix("v"), "// indirect" not in line)
        warnings.append("go.mod declara versões; grafo transitivo completo exige SBOM gerado no ambiente alvo")
    elif name == "pom.xml":
        root = fromstring(text)
        properties = {item.tag.rsplit("}", 1)[-1]: item.text for item in root.findall("{*}properties/*")}
        for key in ("version", "groupId", "artifactId"):
            value = root.findtext("{*}" + key) or root.findtext("{*}parent/{*}" + key)
            properties["project." + key] = value
            properties["pom." + key] = value
        managed = {(item.findtext("{*}groupId"), item.findtext("{*}artifactId")): item.findtext("{*}version") for item in root.findall("{*}dependencyManagement/{*}dependencies/{*}dependency")}
        for item in root.findall("{*}dependencies/{*}dependency"):
            group, artifact, version = item.findtext("{*}groupId"), item.findtext("{*}artifactId"), item.findtext("{*}version")
            version = version or managed.get((group, artifact))
            if version:
                for _ in range(8):
                    previous = version
                    for key, value in properties.items():
                        if value is not None:
                            version = version.replace("${" + key + "}", value)
                    if previous == version:
                        break
            if group and artifact:
                add("Maven", f"{group}:{artifact}", version, True)
            else:
                warnings.append("Dependência Maven sem coordenadas completas")
        warnings.append("POM não resolve propriedades externas, perfis, herança ou dependências transitivas")
    elif name == "gradle.lockfile" or (path.parent.name == "dependency-locks" and name.endswith(".lockfile")):
        for line in text.splitlines():
            match = re.match(r"([^:#]+):([^:]+):([^=]+)=", line)
            if match:
                add("Maven", f"{match[1]}:{match[2]}", match[3])
    elif name == "packages.lock.json":
        for items in json.loads(text).get("dependencies", {}).values():
            for package, item in items.items():
                if item.get("type", "").lower() != "project":
                    add("NuGet", package, item.get("resolved"), item.get("type") == "Direct" if item.get("type") in {"Direct", "Transitive"} else None)
    elif name == "project.assets.json":
        data = json.loads(text)
        direct = {package.lower() for framework in data.get("project", {}).get("frameworks", {}).values() for package in framework.get("dependencies", {})}
        for key, item in data.get("libraries", {}).items():
            if item.get("type") == "package":
                package, version = key.rsplit("/", 1)
                add("NuGet", package, version, package.lower() in direct)
    elif name == "Gemfile.lock":
        direct = set(re.findall(r"^  ([\w.-]+)(?:\s|!|$)", text.split("DEPENDENCIES\n", 1)[-1], re.M))
        registry = False
        for line in text.splitlines():
            if line in {"GEM", "GIT", "PATH"}:
                registry = line == "GEM"
            match = re.match(r"^    ([\w.-]+) \(([^)]+)\)", line)
            if match and registry:
                version = re.split(r"-(?:x86_64|aarch64|arm64|java|x64|x86)(?:-|$)", match[2], 1)[0]
                add("RubyGems", match[1], version, match[1] in direct)
            elif match:
                warnings.append("Dependência Ruby GIT/PATH sem versão de registro comprovada")
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
    if name in {"yarn.lock", "pnpm-lock.yaml", "composer.lock", "poetry.lock", "uv.lock", "Cargo.lock"}:
        companion = path.with_name({"yarn.lock": "package.json", "pnpm-lock.yaml": "package.json", "composer.lock": "composer.json", "Cargo.lock": "Cargo.toml"}.get(name, "pyproject.toml"))
        if companion.is_file():
            try:
                companion_text = read_file(path.parent, companion).decode("utf-8-sig")
                manifest = json.loads(companion_text) if companion.suffix == ".json" else tomllib.loads(companion_text)
                if companion.name == "package.json":
                    declarations = {key: value for group in ("dependencies", "devDependencies", "optionalDependencies") for key, value in manifest.get(group, {}).items()}
                    direct = set(declarations)
                    root_selectors = set()
                    for package, value in declarations.items():
                        if isinstance(value, str):
                            root_selectors.update((f"{package}@{value}", f"{package}@npm:{value}"))
                            if value.startswith("npm:"):
                                direct.add(value[4:].rsplit("@", 1)[0])
                elif companion.name == "composer.json":
                    direct = set(manifest.get("require", {})) | set(manifest.get("require-dev", {}))
                elif companion.name == "Cargo.toml":
                    direct = set().union(*(manifest.get(key, {}) for key in ("dependencies", "dev-dependencies", "build-dependencies")))
                    for group in ("dependencies", "dev-dependencies", "build-dependencies"):
                        for key, value in manifest.get(group, {}).items():
                            if isinstance(value, dict):
                                direct.add(value.get("package", key))
                else:
                    poetry = manifest.get("tool", {}).get("poetry", {})
                    direct = set(poetry.get("dependencies", {})) | set(poetry.get("dev-dependencies", {}))
                    for group in poetry.get("group", {}).values():
                        direct.update(group.get("dependencies", {}))
                    declarations = list(manifest.get("project", {}).get("dependencies", []))
                    for group in manifest.get("project", {}).get("optional-dependencies", {}).values():
                        declarations.extend(group)
                    for group in manifest.get("dependency-groups", {}).values():
                        declarations.extend(value for value in group if isinstance(value, str))
                    for declaration in declarations:
                        match = re.match(r"[A-Za-z0-9_.-]+", declaration)
                        if match:
                            direct.add(re.sub(r"[-_.]+", "-", match[0]).lower())
                for dependency in dependencies:
                    if dependency["direct"] is None:
                        if name == "yarn.lock":
                            dependency["direct"] = bool(yarn_selectors.get((dependency["package"], dependency["version"]), set()) & root_selectors)
                        else:
                            dependency["direct"] = dependency["package"] in direct
            except (ValueError, OSError, TypeError):
                warnings.append("Manifesto complementar indisponível; classificação direta/transitiva não determinada")
    return dependencies, warnings


SUPPORTED = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "poetry.lock",
    "uv.lock",
    "Gemfile.lock",
    "project.assets.json",
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
        if path.name not in SUPPORTED and not path.name.endswith(".cdx.json") and not (path.parent.name == "dependency-locks" and path.name.endswith(".lockfile")):
            continue
        try:
            # Anchor the complete path through directory handles before parsing.
            content = read_file(root, path)
            items, notes = parse_dependencies(path, content)
            for item in items:
                item["file"] = str(path.relative_to(root))
            inventory.extend(items)
            warnings.extend(notes)
        except (ValueError, KeyError, TypeError, OSError) as exc:
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
    semaphore = asyncio.Semaphore(4)

    async def lookup(key):
        async with semaphore:
            try:
                cache[key] = await query_osv(*key)
            except Exception as exc:
                warnings.append(f"Consulta incompleta para {key[1]}: {type(exc).__name__}")
                cache[key] = None

    keys = list(dict.fromkeys((item["ecosystem"], item["package"], item["version"]) for item in inventory))
    if settings.osv_batch and len(keys) > 1:
        try:
            cache.update(await query_osv_batch(keys))
        except Exception:
            pass  # Fallback below still verifies every package and reports any failure.
    pending = [key for key in keys if key not in cache]
    # Bounded batches avoid creating an unbounded number of tasks.
    for start in range(0, len(pending), 40):
        await asyncio.gather(*(lookup(key) for key in pending[start : start + 40]))
    for item in inventory:
        key = (item["ecosystem"], item["package"], item["version"])
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
            # Repository-controlled ignore files must not silently remove coverage.
            # Applicability decisions belong in audited finding triage.
            if path.name in {".semgrepignore", ".gitignore"}:
                continue
            relative = path.relative_to(root)
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            # Refuse symlinks even if the original entry changes during enumeration.
            content = read_file(root, path)
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
            "--disable-nosem",
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
                finding["matched_code"] = "\n".join(lines[max(0, finding.get("start", {}).get("line", 1) - 1) : finding.get("end", {}).get("line", 1)])[:10000]
                snippet = "\n".join(f"{index + 1}: {lines[index]}" for index in range(start, min(end, start + 12)))
                snippet = re.sub(r"(?i)((?:password|secret|api[_-]?key|token)\s*=\s*)[\"'][^\"']+[\"']", r"\1'<redacted>'", snippet)
                snippet = re.sub(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})", "<redacted>", snippet)
                finding.setdefault("extra", {})["lines"] = snippet[:6000]
    import hashlib

    for finding in data.get("results", []):
        matched = finding.pop("matched_code", "")
        finding["code_digest"] = hashlib.sha256("\n".join(line.strip() for line in matched.splitlines()).encode()).hexdigest() if matched else None
    rules_digest = hashlib.sha256(b"".join(rule.read_bytes() for rule in sorted(settings.semgrep_rules.glob("*.y*ml")))).hexdigest()
    return {
        "scope": sorted(scope),
        "rules_digest": rules_digest,
        "engine_version": data.get("version"),
        "findings": data.get("results", []),
        "warnings": data.get("errors", []),
        "coverage": "partial" if data.get("errors") else "rules-only",
        "engine": "Semgrep; somente regras locais, sem prova de explorabilidade",
    }
