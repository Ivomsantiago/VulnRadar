import asyncio
import csv
import io
import json
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Literal
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from . import __version__
from .schemas import TriageInput, PackageQuery, WatchInput, ProjectInput
from .workers import jobs, spawn, scheduler_loop, run_sync, queue_scan, scan_tasks, sync_lock
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DBSession
from .config import settings
from .db import Activity, Advisory, Alias, Project, Scan, Session, Source, Vulnerability, Watch, engine, get_session, now
from .security import authorized_path
from .services.intelligence import query_osv, upsert, normalize, repair_unrated_assessments
from .services.monitoring import check_watch, prioritize, get_epss_threshold
from .services.reporting import cyclone_dx, sarif
from .services.evidence import evidence
from .db import AffectedPackage, Finding, SyncRun
from .logging import configure_logging
from .operations import router as operations_router
from .reports import router as reports_router
from .services.findings import backfill
from .services.notifications import notification_loop
from .services.products import router as products_router, product_rows, ensure_product_index
from .services.history import ensure_baseline
from .services.oci import router as oci_router
from .radar import router as radar_router, recover_collections


@asynccontextmanager
async def lifespan(app):
    configure_logging()
    # Migrations must be applied explicitly; never mutate schema on every startup.
    with Session() as session:
        for scan in session.scalars(select(Scan).where(Scan.status.in_(["running", "pending"]))):
            scan.status = "failed"
            scan.result = {"warnings": ["Execução interrompida; envie uma nova análise"]}
        session.commit()
        backfill(session)
        ensure_baseline(session)
        ensure_product_index(session)
        recover_collections(session)
        repair_unrated_assessments(session)
    spawn(scheduler_loop())
    spawn(notification_loop())
    yield
    for task in list(jobs):
        task.cancel()
    await asyncio.gather(*jobs, return_exceptions=True)
    engine.dispose()


app = FastAPI(title="VulnRadar", version=__version__, lifespan=lifespan)
app.include_router(operations_router)
app.include_router(reports_router)
app.include_router(products_router)
app.include_router(oci_router)
app.include_router(radar_router)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(CORSMiddleware, allow_origins=settings.origins, allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-VulnRadar-Client"])


@app.middleware("http")
async def local_security(request: Request, call_next):
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        if origin and origin not in settings.origins:
            return Response("Origem não autorizada", status_code=403)
        if request.headers.get("X-VulnRadar-Client") != "web":
            return Response("Cabeçalho de cliente obrigatório", status_code=403)
        try:
            length = int(request.headers.get("content-length", "0"))
        except ValueError:
            return Response("Content-Length inválido", status_code=400)
        if length > settings.max_file_bytes:
            return Response("Payload excede o limite", status_code=413)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    return response


@app.get("/api/health")
def health(session: DBSession = Depends(get_session)):
    session.execute(select(func.count()).select_from(Vulnerability))
    return {"status": "ok", "version": __version__}


def filtered(q="", severity=None, kev=None, triage=None):
    stmt = select(Vulnerability)
    if q:
        aliases = select(Alias.vulnerability_id).where(Alias.id.ilike(f"%{q}%"))
        stmt = stmt.where(
            or_(
                Vulnerability.id.in_(aliases),
                Vulnerability.title.ilike(f"%{q}%"),
                Vulnerability.description.ilike(f"%{q}%"),
                Vulnerability.id.in_(
                    select(Advisory.vulnerability_id).join(AffectedPackage, AffectedPackage.advisory_id == Advisory.id).where(AffectedPackage.package.ilike(f"%{q}%"))
                ),
            )
        )
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity.upper())
    if kev is not None:
        stmt = stmt.where(Vulnerability.kev == kev)
    if triage:
        stmt = stmt.where(Vulnerability.triage == triage)
    return stmt


@app.get("/api/vulnerabilities")
def feed(
    q: str = Query("", max_length=200),
    severity: str | None = None,
    kev: bool | None = None,
    triage: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    ecosystem: str | None = None,
    source: str | None = None,
    cvss_min: float | None = Query(None, ge=0, le=10),
    epss_min: float | None = Query(None, ge=0, le=1),
    published_after: str | None = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
    published_before: str | None = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
    modified_after: str | None = Query(None, pattern=r"^\d{4}-\d{2}-\d{2}$"),
    package: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    version: str | None = None,
    project_id: int | None = None,
    cvss_max: float | None = Query(None, ge=0, le=10),
    epss_max: float | None = Query(None, ge=0, le=1),
    sort: Literal["published", "modified", "cvss", "epss", "id"] = "published",
    direction: Literal["asc", "desc"] = "desc",
    session: DBSession = Depends(get_session),
):
    stmt = filtered(q, severity, kev, triage)
    product_matches = {}
    if vendor or product or version:
        for row in product_rows(session, vendor, product, version):
            identifier = row["vulnerability_id"]
            if identifier not in product_matches or row["version_match"] == "affected":
                product_matches[identifier] = row["version_match"]
        stmt = stmt.where(Vulnerability.id.in_(product_matches))
    if ecosystem:
        stmt = stmt.where(
            Vulnerability.id.in_(select(Advisory.vulnerability_id).join(AffectedPackage, AffectedPackage.advisory_id == Advisory.id).where(AffectedPackage.ecosystem == ecosystem))
        )
    if source:
        stmt = stmt.where(Vulnerability.id.in_(select(Advisory.vulnerability_id).where(Advisory.source == source)))
    if cvss_min is not None:
        stmt = stmt.where(Vulnerability.cvss >= cvss_min)
    if epss_min is not None:
        stmt = stmt.where(Vulnerability.epss >= epss_min)
    if published_after:
        stmt = stmt.where(Vulnerability.published >= published_after)
    if published_before:
        stmt = stmt.where(Vulnerability.published < published_before + "T23:59:59.999999Z")
    if modified_after:
        stmt = stmt.where(Vulnerability.modified >= modified_after)
    if cvss_max is not None:
        stmt = stmt.where(Vulnerability.cvss <= cvss_max)
    if epss_max is not None:
        stmt = stmt.where(Vulnerability.epss <= epss_max)
    if package:
        stmt = stmt.where(
            Vulnerability.id.in_(select(Advisory.vulnerability_id).join(AffectedPackage, AffectedPackage.advisory_id == Advisory.id).where(AffectedPackage.package == package))
        )
    if project_id:
        stmt = stmt.where(Vulnerability.id.in_(select(Finding.vulnerability_id).where(Finding.project_id == project_id)))
    total = session.scalar(select(func.count()).select_from(stmt.subquery()))
    column = getattr(Vulnerability, sort)
    ordering = column.desc().nullslast() if direction == "desc" else column.asc().nullslast()
    items = list(session.scalars(stmt.order_by(ordering, Vulnerability.id).offset((page - 1) * page_size).limit(page_size)))
    packages = {}
    for identifier, component in session.execute(
        select(Advisory.vulnerability_id, AffectedPackage)
        .join(AffectedPackage, AffectedPackage.advisory_id == Advisory.id)
        .where(Advisory.vulnerability_id.in_([item.id for item in items]))
    ):
        value = {"ecosystem": component.ecosystem, "package": component.package}
        if value not in packages.setdefault(identifier, []):
            packages[identifier].append(value)
    return {"items": [{**jsonable_encoder(item), "components": packages.get(item.id, []), "version_match": product_matches.get(item.id)} for item in items], "total": total, "page": page, "page_size": page_size, "version_scope": "Versões de produto usam CPE NVD; condições de plataforma/ordenação não verificáveis permanecem desconhecidas" if vendor or product or version else None}


@app.get("/api/vulnerabilities/{identifier}")
def detail(identifier: str, session: DBSession = Depends(get_session)):
    alias = session.get(Alias, identifier)
    item = session.get(Vulnerability, alias.vulnerability_id if alias else identifier)
    if item is None:
        raise HTTPException(404, "Vulnerabilidade não coletada")
    advisories = list(session.scalars(select(Advisory).where(Advisory.vulnerability_id == item.id)))
    return {
        "evidence": [{**evidence(advisory.source, advisory.payload), "updated_at": normalize(advisory.source, advisory.payload).get("modified") if advisory.source in {"osv", "github", "nvd", "trivy", "grype"} else advisory.payload.get("dateAdded")} for advisory in advisories],
        "source_assessments": [{"source": advisory.source, "severity": normalize(advisory.source, advisory.payload)["severity"], "cvss": normalize(advisory.source, advisory.payload)["cvss"], "modified": normalize(advisory.source, advisory.payload).get("modified")} for advisory in advisories if advisory.source in {"osv", "github", "nvd", "trivy", "grype"}],
        "related_projects": [
            {
                "finding_id": finding.id,
                "project_id": finding.project_id,
                "project_name": name,
                "package": finding.package,
                "version": finding.version,
                "scan_id": finding.scan_id,
                "status": finding.status,
            }
            for finding, name in session.execute(
                select(Finding, Project.name).join(Project, Finding.project_id == Project.id).where(Finding.vulnerability_id == item.id).limit(100)
            )
        ],
        "priority": prioritize(item, get_epss_threshold(session)),
        "vulnerability": item,
        "aliases": list(session.scalars(select(Alias.id).where(Alias.vulnerability_id == item.id))),
        "advisories": list(session.scalars(select(Advisory).where(Advisory.vulnerability_id == item.id))),
        "history": list(session.scalars(select(Activity).where(Activity.subject == item.id).order_by(Activity.id.desc()).limit(100))),
    }


@app.patch("/api/vulnerabilities/{identifier}/triage")
def triage(identifier: str, body: TriageInput, session: DBSession = Depends(get_session)):
    item = session.get(Vulnerability, identifier)
    if item is None:
        raise HTTPException(404)
    session.add(Activity(kind="triage", subject=identifier, data={"from": item.triage, "to": body.status, "reason": body.reason}))
    item.triage = body.status
    session.commit()
    return item


@app.get("/api/dashboard")
def dashboard(days: int = Query(30, ge=7, le=90), session: DBSession = Depends(get_session)):
    if days not in {7, 30, 60, 90}:
        raise HTTPException(422, "Período deve ser 7, 30, 60 ou 90 dias")
    counts = dict(session.execute(select(Vulnerability.severity, func.count()).group_by(Vulnerability.severity)).all())
    trend = session.execute(
        select(func.substr(Vulnerability.published, 1, 10), func.count())
        .where(Vulnerability.published >= (now() - timedelta(days=days)).isoformat())
        .group_by(func.substr(Vulnerability.published, 1, 10))
        .order_by(func.substr(Vulnerability.published, 1, 10))
    ).all()
    return {
        "severity_trend": [
            {"date": date, "severity": severity, "count": count}
            for date, severity, count in session.execute(
                select(func.substr(Vulnerability.published, 1, 10), Vulnerability.severity, func.count())
                .where(Vulnerability.published >= (now() - timedelta(days=days)).isoformat())
                .group_by(func.substr(Vulnerability.published, 1, 10), Vulnerability.severity)
                .order_by(func.substr(Vulnerability.published, 1, 10))
            )
        ],
        "new_kev_period": session.scalar(
            select(func.count())
            .select_from(Advisory)
            .where(Advisory.source == "kev", Advisory.payload["dateAdded"].as_string() >= (now() - timedelta(days=days)).date().isoformat())
        ),
        "period_days": days,
        "cvss_distribution": [
            {"label": label, "count": session.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.cvss >= minimum, Vulnerability.cvss < maximum))}
            for label, minimum, maximum in [("0–3.9", 0, 4), ("4–6.9", 4, 7), ("7–8.9", 7, 9), ("9–10", 9, 11)]
        ],
        "epss_distribution": [
            {"label": label, "count": session.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.epss >= minimum, Vulnerability.epss < maximum))}
            for label, minimum, maximum in [("<1%", 0, 0.01), ("1–10%", 0.01, 0.1), ("10–50%", 0.1, 0.5), (">=50%", 0.5, 1.01)]
        ],
        "cvss_missing": session.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.cvss.is_(None))),
        "epss_missing": session.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.epss.is_(None))),
        "new_24h": session.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.published >= (now() - timedelta(hours=24)).isoformat())),
        "total": sum(counts.values()),
        "severities": counts,
        "kev": session.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.kev)),
        "watchlist": session.scalar(select(func.count()).select_from(Watch)),
        "projects": session.scalar(select(func.count()).select_from(Project)),
        "scans": session.scalar(select(func.count()).select_from(Scan)),
        "trend": [{"date": date, "count": count} for date, count in trend],
        "sources": list(session.scalars(select(Source))),
        "coverage": "Indicadores refletem somente a base coletada; não representam toda a internet.",
    }


@app.get("/api/sources")
def sources(session: DBSession = Depends(get_session)):
    existing = {s.id: s for s in session.scalars(select(Source))}
    results = []
    for identifier in ("nvd", "github", "osv", "kev", "epss"):
        state = existing.get(identifier)
        last = session.scalar(select(SyncRun).where(SyncRun.source == identifier).order_by(SyncRun.id.desc()).limit(1))
        success = session.scalar(select(SyncRun.completed_at).where(SyncRun.source == identifier, SyncRun.status == "success").order_by(SyncRun.id.desc()).limit(1))
        payload = jsonable_encoder(state) if state else {"id": identifier, "status": "never", "count": 0}
        health = {"success": "healthy", "running": "syncing", "partial": "partial", "failed": "unavailable"}.get(payload["status"], "never")
        if health == "healthy" and success and (now().replace(tzinfo=None) - success.replace(tzinfo=None)).total_seconds() > settings.sync_minutes * 120:
            health = "stale"
        results.append(
            {
                **payload,
                "health": health,
                "last_success": success,
                "last_sync": last,
                "mode": "package-query" if identifier == "osv" else "incremental" if identifier in {"nvd", "github"} else "catalog",
            }
        )
    return results


@app.post("/api/sources/{source}/sync", status_code=202)
async def sync(source: Literal["nvd", "github", "kev", "epss"]):
    if sync_lock.locked() or len(jobs) >= 8:
        raise HTTPException(409, "Há tarefas em execução; aguarde")
    spawn(run_sync(source))
    return {"status": "queued"}


@app.post("/api/search/package")
async def package_search(body: PackageQuery, session: DBSession = Depends(get_session)):
    source = session.get(Source, "osv")
    if source is None:
        source = Source(id="osv")
        session.add(source)
    source.last_run, source.status = now().isoformat(), "running"
    run = SyncRun(source="osv")
    session.add(run)
    session.commit()
    import time

    started = time.monotonic()
    try:
        rows = await query_osv(body.ecosystem, body.package, body.version)
    except Exception:
        source.status = run.status = "failed"
        run.error = source.error = "OSV indisponível; consulta incompleta"
        run.completed_at = now()
        run.duration_ms = round((time.monotonic() - started) * 1000)
        session.commit()
        raise HTTPException(502, "Consulta OSV incompleta; não é possível concluir ausência de vulnerabilidades")
    items = list({item.id: item for item in [upsert(session, "osv", row, context="package_lookup") for row in rows]}.values())
    source.status = run.status = "success"
    source.count = run.processed_count = len(rows)
    source.error = None
    run.pages = 1
    run.completed_at = now()
    run.duration_ms = round((time.monotonic() - started) * 1000)
    session.commit()
    return {
        "items": items,
        "status": "complete",
        "coverage": "OSV: correspondência de versão, sem análise de alcançabilidade ou garantia de segurança"
        if body.version
        else "Advisories do pacote; versão instalada não informada",
        "query": body.model_dump(),
    }


@app.get("/api/watchlist")
def watches(session: DBSession = Depends(get_session)):
    latest = {}
    for event in session.scalars(select(Activity).where(Activity.kind == "watch.checked").order_by(Activity.id.desc()).limit(2000)):
        latest.setdefault(event.subject, event)
    kev_ids = set(session.scalars(select(Vulnerability.id).where(Vulnerability.kev.is_(True))))
    results = []
    for watch in session.scalars(select(Watch).order_by(Watch.id.desc())):
        event = latest.get(str(watch.id))
        identifiers = event.data.get("vulnerabilities", []) if event else []
        results.append(
            {
                **jsonable_encoder(watch),
                "last_checked": event.created_at if event else None,
                "vulnerability_count": len(identifiers) if event else None,
                "kev_count": len(set(identifiers) & kev_ids) if event else None,
            }
        )
    return results


@app.post("/api/watchlist", status_code=201)
def add_watch(body: WatchInput, session: DBSession = Depends(get_session)):
    existing = session.scalar(select(Watch).where(Watch.ecosystem == body.ecosystem, Watch.package == body.package, Watch.version == body.version))
    if existing:
        raise HTTPException(409, "Este pacote e versão já estão na watchlist")
    item = Watch(**body.model_dump())
    session.add(item)
    session.commit()
    return item


@app.patch("/api/watchlist/{identifier}")
def edit_watch(identifier: int, body: WatchInput, session: DBSession = Depends(get_session)):
    item = session.get(Watch, identifier)
    if not item:
        raise HTTPException(404)
    for name, value in body.model_dump().items():
        setattr(item, name, value)
    session.commit()
    return item


@app.delete("/api/watchlist/{identifier}", status_code=204)
def delete_watch(identifier: int, session: DBSession = Depends(get_session)):
    item = session.get(Watch, identifier)
    if not item:
        raise HTTPException(404)
    session.delete(item)
    session.commit()
    return Response(status_code=204)


@app.get("/api/projects")
def projects(session: DBSession = Depends(get_session)):
    return list(session.scalars(select(Project)))


@app.post("/api/projects", status_code=201)
def add_project(body: ProjectInput, session: DBSession = Depends(get_session)):
    try:
        path = str(authorized_path(body.path))
    except (FileNotFoundError, OSError):
        raise HTTPException(422, "Diretório inexistente")
    if session.scalar(select(Project).where(Project.path == path)):
        raise HTTPException(409, "Projeto já cadastrado")
    item = Project(name=body.name, path=path)
    session.add(item)
    session.commit()
    return item


@app.post("/api/projects/{identifier}/scans/{kind}", status_code=202)
async def create_scan(identifier: int, kind: Literal["sca", "sast", "combined"], session: DBSession = Depends(get_session)):
    if not session.get(Project, identifier):
        raise HTTPException(404)
    if len(jobs) >= 8:
        raise HTTPException(429, "Limite de tarefas atingido")
    item = Scan(project_id=identifier, kind=kind)
    session.add(item)
    session.commit()
    queue_scan(item.id)
    return item


@app.get("/api/scans")
def scans(session: DBSession = Depends(get_session)):
    return list(session.scalars(select(Scan).order_by(Scan.id.desc()).limit(100)))


@app.get("/api/activity")
def activity(kind: str | None = None, session: DBSession = Depends(get_session)):
    stmt = select(Activity)
    if kind:
        stmt = stmt.where(Activity.kind == kind)
    return list(session.scalars(stmt.order_by(Activity.id.desc()).limit(100)))


@app.get("/api/settings")
def get_settings():
    import shutil

    return {
        "sync_minutes": settings.sync_minutes,
        "auto_sync": settings.auto_sync,
        "allowed_roots": settings.allowed_roots,
        "semgrep_available": bool(shutil.which("semgrep")),
        "trivy_available": bool(shutil.which("trivy")),
        "grype_available": bool(shutil.which("grype")),
        "oci_registries": settings.oci_registries,
        "oci_timeout": settings.oci_timeout,
        "webhook_configured": bool(settings.webhook_url and settings.webhook_allowed_hosts),
        "webhook_format": settings.webhook_format,
        "nvd_key_configured": bool(settings.nvd_api_key),
        "github_token_configured": bool(settings.github_token),
        "max_files": settings.max_files,
        "scan_timeout": settings.scan_timeout,
        "remote_deployment": "Autenticação e isolamento adicionais são obrigatórios para uso remoto",
    }


@app.get("/api/export")
def export(format: Literal["csv", "json"] = "json", session: DBSession = Depends(get_session)):
    rows = list(session.scalars(select(Vulnerability).order_by(Vulnerability.id).limit(50000)))
    data = jsonable_encoder(rows)
    if format == "json":
        return Response(json.dumps(data, ensure_ascii=False), media_type="application/json", headers={"Content-Disposition": "attachment; filename=vulnradar.json"})
    output = io.StringIO()
    fields = ["id", "title", "severity", "cvss", "epss", "kev", "triage", "published"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in data:
        writer.writerow({key: "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value for key, value in row.items()})
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=vulnradar.csv"})


@app.get("/api/events")
async def events(request: Request):
    async def stream():
        last = None
        while not await request.is_disconnected():
            with Session() as session:
                current = session.scalar(select(func.max(Activity.id))) or 0
            if current != last:
                yield f"id: {current}\nevent: update\ndata: {json.dumps({'revision': current})}\n\n"
                last = current
            else:
                yield ": heartbeat\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


@app.post("/api/watchlist/{identifier}/check")
async def check_watch_api(identifier: int, session: DBSession = Depends(get_session)):
    if not session.get(Watch, identifier):
        raise HTTPException(404)
    try:
        return await check_watch(session, identifier)
    except Exception:
        session.rollback()
        raise HTTPException(502, "Correlação incompleta: OSV indisponível")


@app.get("/api/scans/{identifier}/export")
def export_scan(identifier: int, format: Literal["json", "sarif", "cyclonedx"] = "json", session: DBSession = Depends(get_session)):
    scan = session.get(Scan, identifier)
    if scan is None:
        raise HTTPException(404)
    if format == "sarif" and scan.kind not in {"sast", "combined"}:
        raise HTTPException(422, "SARIF disponível somente para SAST")
    if format == "cyclonedx" and scan.kind not in {"sca", "combined", "oci"}:
        raise HTTPException(422, "CycloneDX disponível somente para inventário SCA")
    data = scan.result
    if format == "sarif":
        data = sarif(scan.result.get("sast", scan.result).get("findings", []))
    elif format == "cyclonedx":
        data = cyclone_dx(scan.result.get("inventory", []))
    else:
        data = {
            "id": scan.id,
            "project_id": scan.project_id,
            "kind": scan.kind,
            "status": scan.status,
            "created_at": scan.created_at,
            "completed_at": scan.completed_at,
            "result": scan.result,
        }
    return Response(
        json.dumps(jsonable_encoder(data), ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=scan-{identifier}-{format}.json"},
    )


@app.get("/api/scans/{identifier}")
def scan_detail(identifier: int, session: DBSession = Depends(get_session)):
    scan = session.get(Scan, identifier)
    if not scan:
        raise HTTPException(404, "Análise não encontrada")
    return scan


@app.post("/api/sync", status_code=202)
async def sync_all():
    if sync_lock.locked() or len(jobs) >= 8:
        raise HTTPException(409, "Coleta já em execução; acompanhe o estado das fontes")

    async def run_all():
        for source in ("nvd", "github", "kev", "epss"):
            await run_sync(source)

    spawn(run_all())
    return {"status": "queued"}


@app.post("/api/scans/{identifier}/cancel", status_code=202)
async def cancel_scan(identifier: int, session: DBSession = Depends(get_session)):
    scan = session.get(Scan, identifier)
    if not scan:
        raise HTTPException(404)
    task = scan_tasks.get(identifier)
    if scan.status not in {"pending", "running"} or task is None:
        raise HTTPException(409, "Execução não está ativa")
    task.cancel()
    return {"status": "cancelling"}


@app.get("/{path:path}", include_in_schema=False)
def frontend(path: str):
    if path.startswith("api/"):
        raise HTTPException(404)
    root = settings.frontend_dist.resolve()
    target = (root / path).resolve()
    if not target.is_relative_to(root):
        raise HTTPException(403)
    if target.is_file():
        return FileResponse(target)
    index = root / "index.html"
    if index.is_file():
        return FileResponse(index)
    raise HTTPException(404, "Compile o frontend com npm run build")
