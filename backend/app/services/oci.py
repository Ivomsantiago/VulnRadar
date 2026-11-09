"""Historical report normalization; OCI execution has been retired."""

import re
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from ..config import settings
from ..db import get_session, now
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
    raise HTTPException(410, "Análises OCI descontinuadas; use o índice de advisories, consulta de versões e inventário de aplicações")

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
    raise ValueError("Execução OCI descontinuada nesta instalação")
