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
from .schemas import TriageInput, PackageQuery, WatchInput, ProjectInput
from .workers import jobs, spawn, periodic, run_sync, run_scan, sync_lock
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session as DBSession
from .config import settings
from .db import Activity, Advisory, Alias, Project, Scan, Session, Source, Vulnerability, Watch, engine, get_session, now
from .security import authorized_path
from .services.intelligence import query_osv, upsert
from .services.monitoring import check_watch, prioritize
from .services.reporting import cyclone_dx, sarif
from .services.evidence import evidence
from .db import AffectedPackage


@asynccontextmanager
async def lifespan(app):
    # Migrations must be applied explicitly; never mutate schema on every startup.
    with Session() as session:
        for scan in session.scalars(select(Scan).where(Scan.status.in_(["running", "pending"]))):
            scan.status = "failed"
            scan.result = {"warnings": ["Execução interrompida; envie uma nova análise"]}
        session.commit()
    if settings.auto_sync:
        spawn(periodic())
    yield
    for task in list(jobs):
        task.cancel()
    await asyncio.gather(*jobs, return_exceptions=True)
    engine.dispose()


app = FastAPI(title="VulnRadar", version="0.1.0", lifespan=lifespan)
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
    return {"status": "ok", "version": "0.1.0"}


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
    session: DBSession = Depends(get_session),
):
    stmt = filtered(q, severity, kev, triage)
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
    total = session.scalar(select(func.count()).select_from(stmt.subquery()))
    items = list(session.scalars(stmt.order_by(Vulnerability.published.desc(), Vulnerability.id).offset((page - 1) * page_size).limit(page_size)))
    return {"items": items, "total": total, "page": page, "page_size": page_size}


@app.get("/api/vulnerabilities/{identifier}")
def detail(identifier: str, session: DBSession = Depends(get_session)):
    alias = session.get(Alias, identifier)
    item = session.get(Vulnerability, alias.vulnerability_id if alias else identifier)
    if item is None:
        raise HTTPException(404, "Vulnerabilidade não coletada")
    advisories = list(session.scalars(select(Advisory).where(Advisory.vulnerability_id == item.id)))
    return {
        "evidence": [evidence(advisory.source, advisory.payload) for advisory in advisories],
        "priority": prioritize(item),
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
def dashboard(session: DBSession = Depends(get_session)):
    counts = dict(session.execute(select(Vulnerability.severity, func.count()).group_by(Vulnerability.severity)).all())
    trend = session.execute(
        select(func.substr(Vulnerability.published, 1, 10), func.count())
        .where(Vulnerability.published >= (now() - timedelta(days=30)).isoformat())
        .group_by(func.substr(Vulnerability.published, 1, 10))
        .order_by(func.substr(Vulnerability.published, 1, 10))
    ).all()
    return {
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
    return [existing.get(s) or {"id": s, "status": "never", "count": 0} for s in ("nvd", "github", "kev", "epss")]


@app.post("/api/sources/{source}/sync", status_code=202)
async def sync(source: Literal["nvd", "github", "kev", "epss"]):
    if sync_lock.locked() or len(jobs) >= 8:
        raise HTTPException(409, "Há tarefas em execução; aguarde")
    spawn(run_sync(source))
    return {"status": "queued"}


@app.post("/api/search/package")
async def package_search(body: PackageQuery, session: DBSession = Depends(get_session)):
    try:
        rows = await query_osv(body.ecosystem, body.package, body.version)
    except Exception:
        raise HTTPException(502, "Consulta OSV incompleta; não é possível concluir ausência de vulnerabilidades")
    items = [upsert(session, "osv", row) for row in rows]
    session.commit()
    return {"items": items, "status": "complete", "coverage": "OSV: correspondência de versão, sem análise de alcançabilidade ou garantia de segurança"}


@app.get("/api/watchlist")
def watches(session: DBSession = Depends(get_session)):
    return list(session.scalars(select(Watch).order_by(Watch.id.desc())))


@app.post("/api/watchlist", status_code=201)
def add_watch(body: WatchInput, session: DBSession = Depends(get_session)):
    item = Watch(**body.model_dump())
    session.add(item)
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
async def create_scan(identifier: int, kind: Literal["sca", "sast"], session: DBSession = Depends(get_session)):
    if not session.get(Project, identifier):
        raise HTTPException(404)
    if len(jobs) >= 8:
        raise HTTPException(429, "Limite de tarefas atingido")
    item = Scan(project_id=identifier, kind=kind)
    session.add(item)
    session.commit()
    spawn(run_scan(item.id))
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
    if format == "sarif" and scan.kind != "sast":
        raise HTTPException(422, "SARIF disponível somente para SAST")
    if format == "cyclonedx" and scan.kind != "sca":
        raise HTTPException(422, "CycloneDX disponível somente para inventário SCA")
    data = scan.result
    if format == "sarif":
        data = sarif(scan.result.get("findings", []))
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
