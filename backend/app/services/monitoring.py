"""Watchlist correlation and explainable prioritization without invented precision."""

from sqlalchemy import select
from ..db import Activity, Watch
from .intelligence import query_osv, upsert


def prioritize(vulnerability):
    reasons = []
    if vulnerability.kev:
        return {"classification": "Investigação imediata", "reasons": ["Presente no catálogo CISA KEV; aplicabilidade local ainda precisa ser investigada"]}
    if vulnerability.epss is not None and vulnerability.epss >= 0.1:
        reasons.append("EPSS >= 10%; estimativa estatística, sem confirmação de exploração")
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
    if not watch.version:
        return {"status": "incomplete", "items": [], "coverage": "Informe uma versão exata para correlação OSV"}
    rows = await query_osv(watch.ecosystem, watch.package, watch.version)
    items = []
    for raw in rows:
        vulnerability = upsert(session, "osv", raw)
        items.append(vulnerability)
        subject = f"watch:{identifier}:{vulnerability.id}"
        exists = session.scalar(select(Activity.id).where(Activity.kind == "alert", Activity.subject == subject).limit(1))
        if exists is None:
            session.add(
                Activity(
                    kind="alert",
                    subject=subject,
                    data={"reason": "Versão monitorada com advisory OSV", "package": watch.package, "version": watch.version, "vulnerability": vulnerability.id},
                )
            )
    session.commit()
    return {"status": "complete", "items": items, "coverage": "OSV; correspondência de versão, sem prova de explorabilidade"}
