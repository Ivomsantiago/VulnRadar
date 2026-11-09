"""V2 operational API. Exposure always originates in observed scan findings."""

from datetime import timedelta
from typing import Literal
import shutil
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session as DBSession
from .config import settings
from .db import (
    Activity,
    Advisory,
    Alias,
    AffectedPackage,
    Finding,
    FindingObservation,
    InventoryComponent,
    PlatformSetting,
    NotificationDelivery,
    Project,
    Scan,
    SyncRun,
    Vulnerability,
    get_session,
    now,
    utc_datetime,
)
from .schemas import FindingTriageInput
from .services.findings import CLOSED
from .services.monitoring import prioritize, get_epss_threshold
from .services.projects import browse, inspect_project
from .services.evidence import evidence as source_evidence
from .services.history import record_state

router = APIRouter(prefix="/api", tags=["Operations V2"])


def finding_priority(finding, vulnerability=None, epss_threshold=0.1):
    if vulnerability:
        return prioritize(vulnerability, epss_threshold)
    return {
        "classification": "Alta prioridade" if finding.severity in {"HIGH", "CRITICAL"} else "Monitoramento",
        "reasons": ["Severidade da regra SAST; explorabilidade depende de investigação"],
    }


def finding_query(q="", kind=None, project_id=None, status=None):
    stmt = select(Finding, Project.name, Vulnerability).join(Project, Finding.project_id == Project.id).outerjoin(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
    if q:
        stmt = stmt.where(or_(Finding.package.ilike(f"%{q}%"), Finding.vulnerability_id.ilike(f"%{q}%"), Finding.rule_id.ilike(f"%{q}%"), Project.name.ilike(f"%{q}%")))
    if kind:
        stmt = stmt.where(Finding.kind == kind)
    if project_id:
        stmt = stmt.where(Finding.project_id == project_id)
    if status == "open":
        stmt = stmt.where(Finding.status.not_in(CLOSED))
    elif status:
        stmt = stmt.where(Finding.status == status)
    return stmt


def finding_row(finding, project_name, vulnerability, epss_threshold=0.1):
    return {
        **jsonable_encoder(finding),
        "project_name": project_name,
        "vulnerability": jsonable_encoder(vulnerability),
        "priority": finding_priority(finding, vulnerability, epss_threshold),
    }


@router.get("/findings")
def findings(
    q: str = Query("", max_length=200),
    kind: str | None = None,
    scan_id: int | None = None,
    project_id: int | None = None,
    status: str | None = "open",
    severity: str | None = None,
    kev: bool | None = None,
    priority: str | None = None,
    new_hours: int | None = Query(None, ge=1, le=2160),
    sort: Literal["priority", "severity", "newest", "due_at", "owner"] = "priority",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    session: DBSession = Depends(get_session),
):
    stmt = finding_query(q, kind, project_id, status)
    if scan_id:
        stmt = stmt.where(Finding.id.in_(select(FindingObservation.finding_id).where(FindingObservation.scan_id == scan_id)))
    if severity == "HIGH_CRITICAL":
        stmt = stmt.where(Finding.severity.in_(["CRITICAL", "HIGH"]))
    elif severity:
        stmt = stmt.where(Finding.severity == severity)
    if kev is not None:
        stmt = stmt.where(Vulnerability.kev == kev)
    if new_hours:
        stmt = stmt.where(Finding.first_seen >= now() - timedelta(hours=new_hours))
    if priority == "immediate":
        stmt = stmt.where(Vulnerability.kev.is_(True))
    total = session.scalar(select(func.count()).select_from(stmt.subquery()))
    threshold = get_epss_threshold(session)
    stmt = stmt.order_by(
        case(
            (Vulnerability.kev.is_(True), 5),
            (or_(Vulnerability.cvss >= 9, Vulnerability.epss >= threshold, (Finding.kind == "sast") & Finding.severity.in_(["HIGH", "CRITICAL"])), 4),
            (Vulnerability.cvss >= 7, 3),
            else_=1,
        ).desc(),
        case((Finding.severity == "CRITICAL", 4), (Finding.severity == "HIGH", 3), (Finding.severity == "MEDIUM", 2), else_=1).desc(),
        Finding.last_seen.desc(),
        Finding.id.desc(),
    )
    if sort != "priority":
        column = {"newest": Finding.first_seen.desc(), "severity": case((Finding.severity == "CRITICAL", 4), (Finding.severity == "HIGH", 3), (Finding.severity == "MEDIUM", 2), else_=1).desc(), "due_at": Finding.due_at.asc().nullslast(), "owner": Finding.owner.asc().nullslast()}[sort]
        stmt = stmt.order_by(None).order_by(column, Finding.id.desc())
    rows = session.execute(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    return {
        "items": [finding_row(*row, epss_threshold=threshold) for row in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
        "scope": "Achados observados em análises locais; não implica explorabilidade confirmada",
    }


@router.get("/findings/{identifier}")
def finding_detail(identifier: int, session: DBSession = Depends(get_session)):
    row = session.execute(finding_query().where(Finding.id == identifier)).first()
    if row is None:
        raise HTTPException(404, "Achado não encontrado")
    return {
        "source_evidence": source_evidence(row[0].evidence.get("source", "osv"), row[0].evidence.get("advisory", {})) if row[0].kind in {"sca", "oci"} else None,
        **finding_row(*row, epss_threshold=get_epss_threshold(session)),
        "history": list(session.scalars(select(Activity).where(Activity.subject == f"finding:{identifier}").order_by(Activity.id.desc()).limit(100))),
        "observations": list(session.scalars(select(FindingObservation).where(FindingObservation.finding_id == identifier).order_by(FindingObservation.id.desc()).limit(100))),
    }


@router.patch("/findings/{identifier}/triage")
def finding_triage(identifier: int, body: FindingTriageInput, session: DBSession = Depends(get_session)):
    finding = session.get(Finding, identifier)
    if finding is None:
        raise HTTPException(404)
    session.add(
        Activity(kind="finding.triage", subject=f"finding:{identifier}", data={"from": finding.status, "to": body.status, "reason": body.reason, "project_id": finding.project_id})
    )
    expiry = body.risk_expires_at if "risk_expires_at" in body.model_fields_set else finding.risk_expires_at
    if body.status == "accepted" and (expiry is None or utc_datetime(expiry) <= now()):
        raise HTTPException(422, "Aceite de risco exige validade futura")
    changes = {}
    for field in ("owner", "due_at", "risk_expires_at", "remediation_plan"):
        if field in body.model_fields_set:
            changes[field] = {"from": jsonable_encoder(getattr(finding, field)), "to": jsonable_encoder(getattr(body, field))}
            setattr(finding, field, getattr(body, field))
    if changes:
        session.add(Activity(kind="finding.assignment", subject=f"finding:{identifier}", data={"changes": changes, "reason": body.reason}))
    changed_status = finding.status != body.status
    finding.status = body.status
    record_state(session, finding, "resolved" if body.status == "resolved" and changed_status else "triage")
    session.commit()
    return finding


def latest_inventory_query():
    latest = select(func.max(Scan.id)).where(Scan.kind.in_(["sca", "combined"]), Scan.status.in_(["completed", "partial"])).group_by(Scan.project_id)
    images = select(func.max(Scan.id)).where(Scan.kind == "oci", Scan.status.in_(["completed", "partial"])).group_by(Scan.project_id, Scan.result["image"].as_string(), Scan.result["engine"].as_string())
    return select(InventoryComponent, Project.name).join(Project, InventoryComponent.project_id == Project.id).where(or_(InventoryComponent.scan_id.in_(latest), InventoryComponent.scan_id.in_(images)))


@router.get("/inventory")
def inventory(
    q: str = Query("", max_length=200),
    project_id: int | None = None,
    ecosystem: str | None = None,
    direct: bool | None = None,
    sort: Literal["package", "ecosystem", "version"] = "package",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    session: DBSession = Depends(get_session),
):
    stmt = latest_inventory_query()
    if q:
        stmt = stmt.where(InventoryComponent.package.ilike(f"%{q}%"))
    if project_id:
        stmt = stmt.where(InventoryComponent.project_id == project_id)
    if ecosystem:
        stmt = stmt.where(InventoryComponent.ecosystem == ecosystem)
    if direct is not None:
        stmt = stmt.where(InventoryComponent.direct == direct)
    total = session.scalar(select(func.count()).select_from(stmt.subquery()))
    return {
        "items": [
            {**jsonable_encoder(component), "project_name": name}
            for component, name in session.execute(stmt.order_by(getattr(InventoryComponent, sort), InventoryComponent.id).offset((page - 1) * page_size).limit(page_size))
        ],
        "total": total,
        "page_size": page_size,
        "page": page,
    }


@router.get("/exposure")
def exposure(session: DBSession = Depends(get_session)):
    open_filter = Finding.status.not_in(CLOSED)

    def count(*conditions):
        return session.scalar(select(func.count()).select_from(Finding).where(*conditions))

    relevant = session.scalar(select(func.count(func.distinct(Finding.vulnerability_id))).where(open_filter, Finding.kind.in_(["sca", "oci"])))
    kev = session.scalar(
        select(func.count(func.distinct(Finding.vulnerability_id)))
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .where(open_filter, Vulnerability.kev.is_(True))
    )
    latest_scan_ids = select(func.max(Scan.id)).group_by(Scan.project_id, Scan.kind)
    incomplete = session.scalar(select(Scan.id).where(Scan.id.in_(latest_scan_ids), Scan.status.in_(["partial", "failed", "cancelled"])).limit(1))
    return {
        "projects": session.scalar(select(func.count()).select_from(Project)),
        "sca_scanned": session.scalar(select(Scan.id).where(Scan.kind.in_(["sca", "combined"]), Scan.indexed.is_(True)).limit(1)) is not None,
        "sast_scanned": session.scalar(select(Scan.id).where(Scan.kind.in_(["sast", "combined"]), Scan.indexed.is_(True)).limit(1)) is not None,
        "oci_scanned": session.scalar(select(Scan.id).where(Scan.kind == "oci", Scan.indexed.is_(True)).limit(1)) is not None,
        "relevant_vulnerabilities": relevant,
        "open_high_critical": count(open_filter, Finding.severity.in_(["CRITICAL", "HIGH"])),
        "kev": kev,
        "new_24h": session.scalar(
            select(func.count(func.distinct(Finding.vulnerability_id))).where(open_filter, Finding.kind.in_(["sca", "oci"]), Finding.first_seen >= now() - timedelta(hours=24))
        ),
        "open_sca": count(open_filter, Finding.kind == "sca"),
        "open_sast": count(open_filter, Finding.kind == "sast"),
        "open_oci": count(open_filter, Finding.kind == "oci"),
        "resolved": count(Finding.status == "resolved"),
        "scope": "Achados persistidos dos projetos monitorados; correspondência de versão não comprova exploração",
        "state": "no_projects"
        if not session.scalar(select(Project.id).limit(1))
        else "partial"
        if incomplete
        else "observed"
        if session.scalar(select(Scan.id).where(Scan.indexed.is_(True)).limit(1))
        else "not_scanned",
    }


@router.get("/technologies")
def technologies(
    q: str = Query("", max_length=200),
    ecosystem: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    session: DBSession = Depends(get_session),
):
    stmt = (
        select(
            AffectedPackage.ecosystem,
            AffectedPackage.package,
            func.count(func.distinct(Advisory.vulnerability_id)).label("vulnerabilities"),
            func.max(Vulnerability.published).label("last_published"),
            func.count(func.distinct(case((Vulnerability.kev.is_(True), Vulnerability.id), else_=None))).label("kev"),
        )
        .join(Advisory, Advisory.id == AffectedPackage.advisory_id)
        .join(Vulnerability, Vulnerability.id == Advisory.vulnerability_id)
        .group_by(AffectedPackage.ecosystem, AffectedPackage.package)
    )
    if q:
        stmt = stmt.where(AffectedPackage.package.ilike(f"%{q}%"))
    if ecosystem:
        stmt = stmt.where(AffectedPackage.ecosystem == ecosystem)
    total = session.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = session.execute(stmt.order_by(func.count(func.distinct(Advisory.vulnerability_id)).desc(), AffectedPackage.package).offset((page - 1) * page_size).limit(page_size))
    return {
        "items": [dict(row._mapping) for row in rows],
        "total": total,
        "page_size": page_size,
        "page": page,
        "scope": "Pacotes com identidade estruturada nas fontes coletadas; runtimes sem pacote não são inferidos por palavras-chave",
    }


@router.get("/search/universal")
def universal(q: str = Query("", min_length=2, max_length=200), session: DBSession = Depends(get_session)):
    return {
        "vulnerabilities": list(
            session.scalars(
                select(Vulnerability)
                .where(
                    or_(Vulnerability.id.ilike(f"%{q}%"), Vulnerability.title.ilike(f"%{q}%"), Vulnerability.id.in_(select(Alias.vulnerability_id).where(Alias.id.ilike(f"%{q}%"))))
                )
                .limit(8)
            )
        ),
        "projects": list(session.scalars(select(Project).where(Project.name.ilike(f"%{q}%")).limit(6))),
        "packages": [
            dict(row._mapping)
            for row in session.execute(select(AffectedPackage.ecosystem, AffectedPackage.package).where(AffectedPackage.package.ilike(f"%{q}%")).distinct().limit(8))
        ],
    }


@router.get("/directories")
def directories(path: str | None = None):
    try:
        return browse(path)
    except (FileNotFoundError, OSError):
        raise HTTPException(422, "Pasta indisponível no servidor")


@router.get("/projects/{identifier}/inspect")
def project_inspect(identifier: int, session: DBSession = Depends(get_session)):
    project = session.get(Project, identifier)
    if not project:
        raise HTTPException(404)
    return inspect_project(project.path)


@router.get("/engines")
async def engines():
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            response = await client.get("https://api.osv.dev/")
            osv = "reachable" if response.status_code in {200, 404, 405} else "unavailable"
    except httpx.HTTPError:
        osv = "unavailable"
    return {
        "osv": osv,
        "semgrep": bool(shutil.which("semgrep")),
        "trivy": False,
        "grype": False,
        "oci_enabled": False,
        "oci_registries": settings.oci_registries,
        "rules": len(list(settings.semgrep_rules.glob("*.y*ml"))),
        "scope": "Conectividade HTTP; disponibilidade de uma consulta específica é verificada durante o scan",
    }


@router.get("/sync-runs")
def sync_runs(session: DBSession = Depends(get_session)):
    return list(session.scalars(select(SyncRun).order_by(SyncRun.id.desc()).limit(100)))


class Preferences(BaseModel):
    theme: str = Field("dark", pattern="^(dark|light|system)$")
    density: str = Field("compact", pattern="^(compact|comfortable)$")
    epss_threshold: float = Field(0.1, ge=0, le=1)


@router.get("/preferences")
def preferences(session: DBSession = Depends(get_session)):
    value = session.get(PlatformSetting, "preferences")
    return value.value if value else Preferences().model_dump()


@router.patch("/preferences")
def update_preferences(body: Preferences, session: DBSession = Depends(get_session)):
    value = session.get(PlatformSetting, "preferences")
    if value:
        value.value = body.model_dump()
    else:
        session.add(PlatformSetting(key="preferences", value=body.model_dump()))
    session.commit()
    return body


@router.get("/finding-trend")
def finding_trend(days: int = Query(30, ge=1, le=90), session: DBSession = Depends(get_session)):
    cutoff = now() - timedelta(days=days)
    data = {}
    for date, count in session.execute(select(func.date(Finding.first_seen), func.count()).where(Finding.first_seen >= cutoff).group_by(func.date(Finding.first_seen))):
        data[str(date)] = {"date": str(date), "new": count, "resolved": 0}
    # Both manual and evidence-based resolution are events, not inferred trends.
    events = session.scalars(select(Activity).where(Activity.created_at >= cutoff, Activity.kind.in_(["finding.resolved", "finding.triage"])).order_by(Activity.id))
    for event in events:
        if event.kind != "finding.resolved" and event.data.get("to") != "resolved":
            continue
        date = event.created_at.date().isoformat()
        data.setdefault(date, {"date": date, "new": 0, "resolved": 0})["resolved"] += 1
    return [data[key] for key in sorted(data)]


class SchedulerInput(BaseModel):
    enabled: bool = False
    interval_minutes: int = Field(60, ge=5, le=1440)


@router.get("/scheduler")
def scheduler_settings(session: DBSession = Depends(get_session)):
    value = session.get(PlatformSetting, "scheduler")
    return value.value if value else {"enabled": settings.auto_sync, "interval_minutes": max(5, settings.sync_minutes)}


@router.patch("/scheduler")
def scheduler_update(body: SchedulerInput, session: DBSession = Depends(get_session)):
    value = session.get(PlatformSetting, "scheduler")
    previous = value.value if value else {}
    payload = {**previous, **body.model_dump()}
    if value:
        value.value = payload
    else:
        session.add(PlatformSetting(key="scheduler", value=payload))
    session.add(Activity(kind="settings.scheduler", subject="scheduler", data=body.model_dump()))
    session.commit()
    return payload


@router.get("/notification-deliveries")
def notification_deliveries(session: DBSession = Depends(get_session)):
    return list(session.scalars(select(NotificationDelivery).order_by(NotificationDelivery.id.desc()).limit(100)))
