"""Optional CLI adapters scan remote OCI layers without starting containers or Docker."""

import asyncio
import json
import re
import shutil
import os
import tempfile
from pathlib import Path
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from ..config import settings
from ..db import Project, Scan, get_session, now
from .intelligence import severity_name

router = APIRouter(prefix="/api", tags=["OCI analysis"])


def validate_image(value):
    # Explicit registry allowlist prevents inputs from reaching local daemons/files/metadata.
    if len(value) > 500 or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._/:@-]*", value) or "://" in value or ".." in value or value.startswith("-"):
        raise ValueError("Referência OCI inválida; use registro/repositório:tag ou @sha256:digest")
    first = value.split("/", 1)[0]
    registry = first.lower() if "/" in value and ("." in first or ":" in first or first == "localhost") else "docker.io"
    if registry not in settings.oci_registries:
        raise ValueError("Registro OCI fora da lista autorizada do servidor")
    return value


class OCIRequest(BaseModel):
    image: str = Field(min_length=1, max_length=500)
    engine: Literal["trivy", "grype"] = "trivy"

    @field_validator("image")
    @classmethod
    def check_image(cls, value):
        return validate_image(value)


@router.post("/projects/{identifier}/oci", status_code=202)
async def create_scan(identifier: int, body: OCIRequest, session: Session = Depends(get_session)):
    from ..workers import jobs, queue_scan

    if not session.get(Project, identifier):
        raise HTTPException(404, "Projeto não encontrado")
    if not shutil.which(body.engine):
        raise HTTPException(409, f"{body.engine} não instalado no servidor; SCA/SAST continuam disponíveis")
    if len(jobs) >= 8:
        raise HTTPException(429, "Limite de tarefas atingido")
    item = Scan(project_id=identifier, kind="oci", result={"request": body.model_dump()})
    session.add(item)
    session.commit()
    queue_scan(item.id)
    return item


def normalize_report(engine, data, image):
    inventory, findings, warnings = {}, [], []

    def component(package, version, ecosystem, path="", purl=None):
        if not package or not version:
            warnings.append("Componente OCI sem nome/versão; correspondência não determinada")
            return None
        key = (ecosystem, package, version, path)
        inventory[key] = {"ecosystem": ecosystem, "package": package, "version": version, "file": path or image, "direct": None, "query_status": "complete", "purl": purl}
        return inventory[key]

    def finding(dependency, raw, identifier, title, severity, fixed, references, aliases=()):
        if dependency is None or not identifier:
            return
        advisory = {
            "id": identifier,
            "aliases": list(aliases),
            "summary": title or identifier,
            "details": raw.get("Description", raw.get("description", "")) or "",
            "database_specific": {"severity": severity_name(severity)},
            "modified": raw.get("LastModifiedDate"),
            "affected": [
                {
                    "package": {"ecosystem": dependency["ecosystem"], "name": dependency["package"]},
                    "versions": [dependency["version"]],
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": value} for value in fixed]}],
                }
            ],
            "references": [{"url": value} for value in references if isinstance(value, str)],
            "original": raw,
        }
        findings.append(
            {"source": engine, "dependency": dependency, "advisory": advisory, "evidence": f"Correspondência de componente/versão por {engine}; explorabilidade não avaliada"}
        )

    if engine == "trivy":
        if "Results" not in data and "Metadata" not in data:
            raise ValueError("Resposta Trivy sem identificação do artefato")
        for result in data.get("Results") or []:
            ecosystem = result.get("Type", "unknown")
            for package in result.get("Packages") or []:
                component(package.get("Name"), package.get("Version"), ecosystem, result.get("Target", ""), package.get("Identifier", {}).get("PURL"))
            for raw in result.get("Vulnerabilities") or []:
                dependency = component(raw.get("PkgName"), raw.get("InstalledVersion"), ecosystem, result.get("Target", ""), raw.get("PkgIdentifier", {}).get("PURL"))
                fixed = [value.strip() for value in raw.get("FixedVersion", "").split(",") if value.strip()]
                finding(dependency, raw, raw.get("VulnerabilityID"), raw.get("Title"), raw.get("Severity"), fixed, raw.get("References") or [])
            if result.get("Error"):
                warnings.append("Trivy informou erro de cobertura em um componente")
        if data.get("Metadata", {}).get("OS", {}).get("EOSL"):
            warnings.append("Distribuição fora de suporte; cobertura de advisories pode ser insuficiente")
        digest = next(iter(data.get("Metadata", {}).get("RepoDigests") or []), data.get("Metadata", {}).get("ImageID"))
        digest_type = "repository" if data.get("Metadata", {}).get("RepoDigests") else "image-config"
        if not inventory:
            warnings.append("Imagem sem componentes reconhecidos pelo Trivy")
    else:
        if "matches" not in data or not data.get("source"):
            raise ValueError("Resposta Grype sem identificação do artefato")
        for match in data.get("matches", []):
            raw, artifact = match.get("vulnerability", {}), match.get("artifact", {})
            dependency = component(artifact.get("name"), artifact.get("version"), artifact.get("type", "unknown"), "", artifact.get("purl"))
            related = [value.get("id") for value in match.get("relatedVulnerabilities", []) if value.get("id")]
            finding(dependency, raw, raw.get("id"), raw.get("description"), raw.get("severity"), raw.get("fix", {}).get("versions") or [], raw.get("urls") or [], related)
        target = data.get("source", {}).get("target")
        target = target if isinstance(target, dict) else {}
        digest = next(iter(target.get("repoDigests") or []), target.get("manifestDigest") or target.get("imageID"))
        digest_type = "repository" if target.get("repoDigests") else "manifest" if target.get("manifestDigest") else "image-config"
        database = data.get("descriptor", {}).get("db", {})
        database_status = database.get("status")
        database_valid = database_status.get("valid", False) if isinstance(database_status, dict) else database_status in (None, "valid")
        if database.get("error") or not database_valid:
            warnings.append("Grype informou base de advisories incompleta ou inválida")
    status = data.get("descriptor", {}).get("db", {}).get("status", {})
    updated = status.get("built") if isinstance(status, dict) else None
    return {
        "engine": engine,
        "image": image,
        "digest": digest,
        "digest_type": digest_type,
        "scope": [image],
        "inventory": list(inventory.values()),
        "inventory_scope": "Todos os componentes reconhecidos" if engine == "trivy" else "Componentes citados nos achados; catálogo completo interno ao Grype",
        "findings": findings,
        "warnings": warnings,
        "coverage": "partial" if warnings else "complete",
        "source_updated": updated,
        "scanned_at": now().isoformat(),
    }


async def oci(image, engine, progress=None):
    validate_image(image)
    executable = shutil.which(engine)
    if engine not in {"trivy", "grype"} or not executable:
        raise ValueError("Mecanismo OCI opcional não disponível")
    if progress:
        await progress("oci")
    with tempfile.TemporaryDirectory(prefix="vulnradar-oci-") as temporary:
        config = Path(temporary) / "config.yaml"
        config.write_text("{}", encoding="utf-8")
        args = (
            [
                "image",
                "--config",
                str(config),
                "--image-src",
                "remote",
                "--scanners",
                "vuln",
                "--format",
                "json",
                "--list-all-pkgs",
                "--no-progress",
                "--timeout",
                f"{settings.oci_timeout}s",
                image,
            ]
            if engine == "trivy"
            else ["--config", str(config), "registry:" + image, "--output", "json", "--quiet"]
        )
        process = await asyncio.create_subprocess_exec(
            executable, *args, cwd=temporary, env={**os.environ, "GOMAXPROCS": "2", "GOMEMLIMIT": "512MiB"}, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )

        async def read(stream, limit):
            content = bytearray()
            while chunk := await stream.read(65536):
                content.extend(chunk)
                if len(content) > limit:
                    raise ValueError("Saída OCI excede o limite de recursos")
            return bytes(content)

        tasks = [asyncio.create_task(read(process.stdout, 50_000_000)), asyncio.create_task(read(process.stderr, 1_000_000)), asyncio.create_task(process.wait())]
        try:
            stdout, _, _ = await asyncio.wait_for(asyncio.gather(*tasks), settings.oci_timeout)
            if process.returncode != 0:
                raise ValueError(f"{engine} terminou com código {process.returncode}; confirme imagem, registro e base de advisories")
            return normalize_report(engine, json.loads(stdout), image)
        finally:
            if process.returncode is None:
                process.kill()
            await process.wait()
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
