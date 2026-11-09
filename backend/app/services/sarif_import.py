"""Bounded SARIF 2.1.0 ingestion; never opens source or resolves artifact URIs."""
import hashlib
import json
from pathlib import PurePosixPath
import re
from urllib.parse import unquote, urlsplit

from jsonschema import Draft7Validator, FormatChecker
from ..config import settings
from ..db import Activity, Scan, now
from .findings import index_scan


def validator():
    path = settings.semgrep_rules.parent / "schemas" / "sarif-2.1.0.json"
    return Draft7Validator(json.loads(path.read_text(encoding="utf-8")), format_checker=FormatChecker())


def artifact_path(location, run):
    artifact = location.get("physicalLocation", {}).get("artifactLocation", {})
    if "uri" not in artifact and "index" in artifact:
        index = artifact["index"]
        artifacts = run.get("artifacts", [])
        if not 0 <= index < len(artifacts):
            raise ValueError("SARIF referencia artefato inexistente")
        artifact = artifacts[index].get("location", {})
    uri = unquote(artifact.get("uri", "unknown-location")).replace("\\", "/")
    parts = urlsplit(uri)
    if parts.scheme not in {"", "file"} or parts.netloc or len(uri) > 2000 or any(ord(char) < 32 for char in uri):
        raise ValueError("Localização SARIF inválida; links remotos não são aceitos")
    path = PurePosixPath(parts.path)
    if ".." in path.parts:
        raise ValueError("Localização SARIF contém traversal")
    # Absolute paths are evidence labels only, never filesystem inputs.
    return path.as_posix().lstrip("/")


def normalize_sarif(document):
    runs = document.get("runs")
    if not isinstance(runs, list) or not all(isinstance(run, dict) and isinstance(run.get("results", []), list) for run in runs):
        raise ValueError("Estrutura SARIF inválida")
    if not 1 <= len(runs) <= 10 or sum(len(run.get("results", [])) for run in runs) > 2000:
        raise ValueError("SARIF exige 1-10 runs e no máximo 2000 resultados")
    if not validator().is_valid(document):
        raise ValueError("Documento não atende ao schema SARIF 2.1.0")
    findings, engines = [], []
    for run in runs:
        if run.get("externalPropertyFileReferences"):
            raise ValueError("SARIF precisa ser autocontido; propriedades externas não são carregadas")
        driver = run["tool"]["driver"]
        tool = re.sub(r"[^A-Za-z0-9_.-]", "_", driver["name"])[:80]
        engines.append({"tool": tool, "version": driver.get("semanticVersion", driver.get("version"))})
        rules = {rule["id"]: rule for rule in driver.get("rules", [])}
        for result in run.get("results", []):
            rule = result.get("ruleId")
            if not rule or len(rule) > 200:
                raise ValueError("Cada resultado SARIF exige ruleId de até 200 caracteres")
            locations = result.get("locations", [])
            location = locations[0] if locations else {}
            path = artifact_path(location, run)
            region = location.get("physicalLocation", {}).get("region", {})
            text = result["message"].get("text", rule)[:4000]
            metadata = rules.get(rule, {}).get("properties", {})
            cwes = sorted(set(re.findall(r"CWE-\d+", json.dumps(metadata))))[:30]
            identity = result.get("partialFingerprints") or {"rule": rule, "path": path, "message": text}
            findings.append({"check_id": f"sarif:{tool}:{rule}", "path": path,
                             "start": {"line": region.get("startLine", 1)}, "end": {"line": region.get("endLine", region.get("startLine", 1))},
                             "code_digest": hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
                             "extra": {"message": text, "severity": {"error": "ERROR", "warning": "WARNING", "note": "INFO", "none": "INFO"}.get(result.get("level", "warning")), "metadata": {"cwe": cwes}},
                             "source": "sarif", "imported_tool": tool})
    return {"findings": findings, "inventory": [], "coverage": "partial", "warnings": ["SARIF importado: declaração de ferramenta externa, sem comprovação local de cobertura ou explorabilidade; ausência não resolve achados"], "engine": "SARIF import", "tools": engines}


def import_sarif(session, project_id, document):
    result = normalize_sarif(document)
    result["artifact_sha256"] = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
    scan = Scan(project_id=project_id, kind="sast", status="partial", stage="partial", result=result, completed_at=now())
    session.add(scan)
    session.flush()
    index_scan(session, scan)
    session.add(Activity(kind="scan.imported", subject=str(scan.id), data={"project_id": project_id, "format": "sarif", "artifact_sha256": result["artifact_sha256"]}))
    session.commit()
    return scan
