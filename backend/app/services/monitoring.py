"""Watchlist correlation and explainable prioritization without invented precision."""

from sqlalchemy import select
from ..db import Activity, Watch, PlatformSetting
from .intelligence import query_osv, upsert
from .findings import SEVERITY_ORDER, fingerprint


def get_epss_threshold(session):
    preference = session.get(PlatformSetting, "preferences")
    return preference.value.get("epss_threshold", 0.1) if preference else 0.1


def prioritize(vulnerability, epss_threshold=0.1):
    reasons = []
    if vulnerability.kev:
        return {"classification": "Investigação imediata", "reasons": ["Presente no catálogo CISA KEV; aplicabilidade local ainda precisa ser investigada"]}
    if vulnerability.epss is not None and vulnerability.epss >= epss_threshold:
        reasons.append(f"EPSS >= {epss_threshold:.1%}; estimativa estatística, sem confirmação de exploração")
    if vulnerability.cvss is not None and vulnerability.cvss >= 9:
        reasons.append("CVSS >= 9; severidade técnica crítica")
    if reasons:
        return {"classification": "Alta prioridade", "reasons": reasons}
    if vulnerability.cvss is None and vulnerability.epss is None:
        return {"classification": "Dados insuficientes", "reasons": ["CVSS e EPSS não informados"]}
    return {
        "classification": "Prioridade moderada" if (vulnerability.cvss or 0) >= 7 else "Monitoramento",
        "reasons": ["Classificação preliminar; exposição e criticidade local não avaliadas"],
    }


async def check_watch(session, identifier):
    watch = session.get(Watch, identifier)
    if watch is None:
        raise ValueError("Item não encontrado")
    rows = await query_osv(watch.ecosystem, watch.package, watch.version)
    items = []
    for raw in rows:
        vulnerability = upsert(session, "osv", raw, context="watch")
        items.append(vulnerability)
        material = fingerprint([raw.get("affected"), raw.get("severity"), raw.get("database_specific")])[:16]
        subject = f"watch:{identifier}:{vulnerability.id}:{material}"
        exists = session.scalar(select(Activity.id).where(Activity.kind == "alert", Activity.subject == subject).limit(1))
        if exists is None and watch.alerts_enabled and SEVERITY_ORDER.get(vulnerability.severity, 0) >= SEVERITY_ORDER.get(watch.min_severity, 0):
            session.add(
                Activity(
                    kind="alert",
                    subject=subject,
                    data={"reason": "Versão monitorada com advisory OSV", "package": watch.package, "version": watch.version, "vulnerability": vulnerability.id},
                )
            )
    session.add(
        Activity(kind="watch.checked", subject=str(identifier), data={"vulnerabilities": sorted({item.id for item in items}), "version": watch.version, "status": "complete"})
    )
    session.commit()
    return {
        "status": "complete",
        "items": items,
        "coverage": "OSV; correspondência de versão, sem prova de explorabilidade" if watch.version else "Advisories do pacote; versão instalada não informada",
    }
