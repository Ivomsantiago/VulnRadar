"""Version-bound not-affected assertions, with explicit operator approval to apply."""
from datetime import datetime
import hashlib
import json
from sqlalchemy import select
from ..db import Activity, Alias, VexStatement, now, utc_datetime
from ..security_context import actor
from ..input_budget import check_structure
from .history import record_state
from .reporting import cyclone_dx
from .schema_validation import cyclonedx_validator

JUSTIFICATIONS = {"component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path", "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist"}
CDX_JUSTIFICATIONS = {"component_not_present": "code_not_present", "vulnerable_code_not_present": "code_not_present", "vulnerable_code_not_in_execute_path": "code_not_reachable", "inline_mitigations_already_exist": "protected_at_runtime"}


def component_purl(finding):
    if finding.kind != "sca" or not all((finding.package, finding.ecosystem, finding.version, finding.vulnerability_id)):
        raise ValueError("VEX exige achado SCA com pacote, versão e vulnerabilidade identificados")
    component = cyclone_dx([{"ecosystem": finding.ecosystem, "package": finding.package, "version": finding.version}])["components"][0]
    if "purl" not in component:
        raise ValueError("Ecossistema sem identidade PURL suportada")
    return component["purl"]


def import_vex(session, finding, document, format, apply_decision, operator_reason):
    check_structure(document)
    purl = component_purl(finding)
    aliases = set(session.scalars(select(Alias.id).where(Alias.vulnerability_id == finding.vulnerability_id))) | {finding.vulnerability_id}
    candidates = []
    if format == "openvex":
        if document.get("@context") != "https://openvex.dev/ns/v0.2.0" or not document.get("author") or not document.get("@id") or not isinstance(document.get("version"), int):
            raise ValueError("OpenVEX exige contexto 0.2.0, identificador, autor e versão")
        statements = document.get("statements", [])
        if not isinstance(statements, list) or not 1 <= len(statements) <= 1000:
            raise ValueError("OpenVEX exige 1-1000 declarações autocontidas")
        for statement in statements:
            if statement.get("vulnerability", {}).get("name") in aliases and any(product.get("@id") == purl for product in statement.get("products", [])):
                if statement.get("status") != "not_affected" or statement.get("justification") not in JUSTIFICATIONS:
                    raise ValueError("Este fluxo exige status not_affected e justificativa OpenVEX reconhecida")
                candidates.append((statement["justification"], statement.get("impact_statement", statement["justification"]), statement.get("timestamp", document.get("timestamp"))))
    else:
        if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.5":
            raise ValueError("Este fluxo suporta CycloneDX VEX JSON 1.5")
        if len(document.get("vulnerabilities", [])) > 1000 or len(document.get("components", [])) > 5000:
            raise ValueError("CycloneDX VEX excede o limite de declarações/componentes")
        if not cyclonedx_validator().is_valid(document):
            raise ValueError("Documento não atende ao schema CycloneDX 1.5")
        refs = {component.get("bom-ref") for component in document.get("components", []) if component.get("purl") == purl}
        for vulnerability in document.get("vulnerabilities", []):
            if vulnerability.get("id") in aliases and any(item.get("ref") in refs for item in vulnerability.get("affects", [])):
                analysis = vulnerability.get("analysis", {})
                justification = next((key for key, value in CDX_JUSTIFICATIONS.items() if value == analysis.get("justification")), None)
                if analysis.get("state") != "not_affected" or justification is None:
                    raise ValueError("CycloneDX VEX exige not_affected e justificativa suportada")
                candidates.append((justification, analysis.get("detail", justification), analysis.get("lastUpdated", document.get("metadata", {}).get("timestamp"))))
    if len(candidates) != 1:
        raise ValueError("VEX precisa identificar exatamente uma declaração para esta vulnerabilidade e versão PURL instalada")
    justification, reason, timestamp = candidates[0]
    try:
        issued = utc_datetime(datetime.fromisoformat(timestamp))
    except (ValueError, TypeError):
        raise ValueError("VEX exige timestamp válido com fuso horário")
    if datetime.fromisoformat(timestamp).tzinfo is None or issued > now():
        raise ValueError("VEX exige timestamp com fuso e não futuro")
    reason = str(reason)[:4000]
    if apply_decision and (not operator_reason or len(operator_reason.strip()) < 3):
        raise ValueError("Aplicar VEX à triagem exige justificativa do analista")
    digest = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
    statement = VexStatement(finding_id=finding.id, package_version=finding.version, format=format, artifact_sha256=digest, justification=justification, reason=reason, author=actor.get(), issued_at=issued, applied=apply_decision)
    session.add(statement)
    session.add(Activity(kind="vex.imported", subject=f"finding:{finding.id}", data={"artifact_sha256": digest, "format": format, "justification": justification, "applied": apply_decision, "reason": operator_reason}))
    if apply_decision:
        previous = finding.status
        finding.status = "not_applicable"
        session.add(Activity(kind="finding.triage", subject=f"finding:{finding.id}", data={"from": previous, "to": "not_applicable", "reason": operator_reason, "source": "vex", "artifact_sha256": digest}))
        record_state(session, finding, "triage")
    session.commit()
    return {"id": statement.id, "finding_id": finding.id, "version": finding.version, "justification": justification, "applied": apply_decision, "artifact_sha256": digest}


def export_vex(session, finding, format):
    purl = component_purl(finding)
    statement = session.scalar(select(VexStatement).where(VexStatement.finding_id == finding.id, VexStatement.package_version == finding.version, VexStatement.applied.is_(True)).order_by(VexStatement.id.desc()).limit(1))
    if statement is None or finding.status != "not_applicable":
        raise ValueError("Exportação exige declaração VEX aplicada e triagem ainda não aplicável nesta versão")
    timestamp = utc_datetime(statement.issued_at).isoformat()
    if format == "openvex":
        return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "urn:sha256:" + statement.artifact_sha256, "author": statement.author, "timestamp": timestamp, "version": 1, "statements": [{"vulnerability": {"name": finding.vulnerability_id}, "products": [{"@id": purl}], "status": "not_affected", "justification": statement.justification, "impact_statement": statement.reason}]}
    if statement.justification not in CDX_JUSTIFICATIONS:
        raise ValueError("Justificativa sem conversão CycloneDX inequívoca; exporte OpenVEX")
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "metadata": {"timestamp": timestamp}, "components": [{"type": "library", "bom-ref": purl, "name": finding.package, "version": finding.version, "purl": purl}], "vulnerabilities": [{"id": finding.vulnerability_id, "affects": [{"ref": purl}], "analysis": {"state": "not_affected", "justification": CDX_JUSTIFICATIONS[statement.justification], "detail": statement.reason, "lastUpdated": timestamp}}]}
