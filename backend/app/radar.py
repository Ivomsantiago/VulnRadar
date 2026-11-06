"""Publication-window intelligence: explicit collection, exact periods and triage."""

import asyncio
import csv
import io
from datetime import datetime, timedelta
from typing import Literal
import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select, func, case, or_, cast, DateTime
from sqlalchemy.orm import Session as DBSession
from .config import settings
from .db import Activity, Advisory, Alias, AffectedPackage, RadarCollection, Session, Source, SyncRun, Vulnerability, get_session, now, utc_datetime
from .services.intelligence import URLS, fetch_kev, github_next_page, github_timestamp, normalize, request, upsert

router = APIRouter(prefix="/api/radar", tags=["Publication radar"])
collection_tasks = {}


def collection_row(job):
    value = jsonable_encoder(job)
    for key in ("since", "until", "created_at", "completed_at"):
        date = getattr(job, key)
        value[key] = utc_datetime(date).isoformat() if date else None
    return value


def period_window(period="24h", since=None, until=None):
    if period == "custom" and (since is None or until is None):
        raise HTTPException(422, "O período personalizado exige início e fim")
    end = utc_datetime(until) if until else now()
    start = utc_datetime(since) if since else end - timedelta(hours={"24h": 24, "7d": 168, "30d": 720, "90d": 2160}.get(period, 24))
    if start >= end or end - start > timedelta(days=366) or end > now() + timedelta(minutes=5):
        raise HTTPException(422, "Escolha um intervalo válido de até 366 dias, sem data final no futuro")
    return start, end


def date_column(session, column):
    return func.julianday(column) if session.get_bind().dialect.name == "sqlite" else cast(column, DateTime(timezone=True))


def radar_query(session, since, until, basis="published", q="", severity="urgent", state="all", source=None, kev=False):
    column = date_column(session, getattr(Vulnerability, basis))
    lower = func.julianday(since.isoformat()) if session.get_bind().dialect.name == "sqlite" else since
    upper = func.julianday(until.isoformat()) if session.get_bind().dialect.name == "sqlite" else until
    statement = select(Vulnerability).where(column >= lower, column <= upper)
    if q:
        statement = statement.where(
            or_(
                Vulnerability.id.ilike(f"%{q}%"),
                Vulnerability.title.ilike(f"%{q}%"),
                Vulnerability.description.ilike(f"%{q}%"),
                Vulnerability.id.in_(select(Alias.vulnerability_id).where(Alias.id.ilike(f"%{q}%"))),
                Vulnerability.id.in_(
                    select(Advisory.vulnerability_id).join(AffectedPackage, AffectedPackage.advisory_id == Advisory.id).where(AffectedPackage.package.ilike(f"%{q}%"))
                ),
            )
        )
    if severity == "urgent":
        statement = statement.where(Vulnerability.severity.in_(["CRITICAL", "HIGH"]))
    elif severity != "all":
        statement = statement.where(Vulnerability.severity == severity)
    if state == "queued":
        statement = statement.where(Vulnerability.triage.in_(["investigating", "planned", "remediating"]))
    elif state != "all":
        statement = statement.where(Vulnerability.triage == state)
    if source:
        statement = statement.where(Vulnerability.id.in_(select(Advisory.vulnerability_id).where(Advisory.source == source)))
    if kev:
        statement = statement.where(Vulnerability.kev.is_(True))
    return statement


@router.get("")
def radar(
    period: Literal["24h", "7d", "30d", "90d", "custom"] = "24h",
    since: datetime | None = None,
    until: datetime | None = None,
    basis: Literal["published", "modified"] = "published",
    q: str = Query("", max_length=200),
    severity: Literal["urgent", "all", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] = "urgent",
    state: str = Query("all", max_length=30),
    source: str | None = None,
    kev: bool = False,
    sort: Literal["priority", "newest", "epss"] = "priority",
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    format: Literal["json", "csv"] = "json",
    export: bool = False,
    session: DBSession = Depends(get_session),
):
    start, end = period_window(period, since, until)
    statement = radar_query(session, start, end, basis, q, severity, state, source, kev)
    # Summary represents this time window/search/source, independent of severity/queue chips.
    base = radar_query(session, start, end, basis, q, "all", "all", source)
    counts = dict(
        session.execute(select(Vulnerability.severity, func.count()).where(Vulnerability.id.in_(base.with_only_columns(Vulnerability.id))).group_by(Vulnerability.severity)).all()
    )
    summary = {
        "total": sum(counts.values()),
        "critical": counts.get("CRITICAL", 0),
        "high": counts.get("HIGH", 0),
        "unknown": counts.get("UNKNOWN", 0),
        "kev": session.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.id.in_(base.with_only_columns(Vulnerability.id)), Vulnerability.kev.is_(True))),
        "queued": session.scalar(
            select(func.count())
            .select_from(Vulnerability)
            .where(Vulnerability.id.in_(base.with_only_columns(Vulnerability.id)), Vulnerability.triage.in_(["investigating", "planned", "remediating"]))
        ),
    }
    rank = case(
        (Vulnerability.severity == "CRITICAL", 5), (Vulnerability.severity == "HIGH", 4), (Vulnerability.severity == "MEDIUM", 3), (Vulnerability.severity == "LOW", 2), else_=1
    )
    ordering = [
        rank.desc(),
        Vulnerability.kev.desc(),
        Vulnerability.epss.desc().nullslast(),
        Vulnerability.cvss.desc().nullslast(),
        date_column(session, getattr(Vulnerability, basis)).desc(),
        Vulnerability.id,
    ]
    if sort != "priority":
        ordering = (
            [date_column(session, getattr(Vulnerability, basis)).desc(), Vulnerability.id]
            if sort == "newest"
            else [Vulnerability.epss.desc().nullslast(), rank.desc(), Vulnerability.id]
        )
    total = session.scalar(select(func.count()).select_from(statement.subquery()))
    rows = list(
        session.scalars(statement.order_by(*ordering).offset(0 if export or format == "csv" else (page - 1) * page_size).limit(5000 if export or format == "csv" else page_size))
    )
    sources = {}
    for identifier, value in session.execute(select(Advisory.vulnerability_id, Advisory.source).where(Advisory.vulnerability_id.in_([row.id for row in rows])).distinct()):
        sources.setdefault(identifier, []).append(value)
    items = [{**jsonable_encoder(row), "sources": sorted(sources.get(row.id, []))} for row in rows]
    payload = {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "summary": summary,
        "window": {"since": start, "until": end, "basis": basis},
        "truncated": bool((export or format == "csv") and total > len(rows)),
        "scope": "Inteligência publicada/atualizada nas fontes coletadas. A fila organiza investigação; não confirma exposição dos seus repositórios.",
    }
    if format == "json":
        return payload
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "title", "severity", "cvss", "epss", "kev", "published", "modified", "triage", "sources"], extrasaction="ignore")
    writer.writeheader()
    for item in items:
        writer.writerow({key: "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")) else value for key, value in item.items()})
    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnradar-periodo.csv", "X-Export-Total": str(total), "X-Export-Truncated": str(total > len(rows)).lower()},
    )


class CollectionInput(BaseModel):
    since: datetime
    until: datetime
    basis: Literal["published", "modified"] = "published"
    enrich: bool = True

    @model_validator(mode="after")
    def dates(self):
        self.since, self.until = period_window(since=self.since, until=self.until)
        return self


def recover_collections(session):
    for job in session.scalars(select(RadarCollection).where(RadarCollection.status.in_(["pending", "running"]))):
        job.status, job.completed_at = "failed", now()
        job.progress = {**job.progress, "error": "Coleta interrompida; resultados já salvos foram preservados. Execute novamente o período."}
    session.commit()


@router.get("/collections")
def collections(session: DBSession = Depends(get_session)):
    return [collection_row(job) for job in session.scalars(select(RadarCollection).order_by(RadarCollection.id.desc()).limit(10))]


@router.post("/collect", status_code=202)
async def collect(body: CollectionInput, session: DBSession = Depends(get_session)):
    from .workers import spawn

    if session.scalar(select(RadarCollection.id).where(RadarCollection.status.in_(["pending", "running"]))):
        raise HTTPException(409, "Já existe uma coleta de período em andamento")
    job = RadarCollection(since=body.since, until=body.until, basis=body.basis, enrich=body.enrich, progress={"sources": {}, "fetched": 0, "pages": 0})
    session.add(job)
    session.commit()
    task = spawn(run_collection(job.id))
    collection_tasks[job.id] = task
    task.add_done_callback(lambda _: collection_tasks.pop(job.id, None))
    return collection_row(job)


@router.post("/collections/{identifier}/cancel")
async def cancel(identifier: int, session: DBSession = Depends(get_session)):
    job = session.get(RadarCollection, identifier)
    if not job:
        raise HTTPException(404)
    if job.status not in {"pending", "running"}:
        raise HTTPException(409, "Coleta já encerrada")
    if identifier in collection_tasks:
        collection_tasks[identifier].cancel()
    job.status, job.completed_at = "cancelled", now()
    session.commit()
    return collection_row(job)


async def collect_source(session, job, source, client, targets):
    start, end = utc_datetime(job.since), utc_datetime(job.until)
    fetched, pages, new_count, updated_count = 0, 0, 0, 0
    while start < end:
        window_end = min(start + timedelta(days=119), end) if source == "nvd" else end
        page = 0
        github_cursor, seen_github_cursors = {}, set()
        while True:
            if source == "nvd":
                prefix = "pub" if job.basis == "published" else "lastMod"
                params = {prefix + "StartDate": start.isoformat(), prefix + "EndDate": window_end.isoformat(), "startIndex": page * 2000, "resultsPerPage": 2000}
                headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
            else:
                params = {
                    "published" if job.basis == "published" else "modified": f"{github_timestamp(start)}..{github_timestamp(window_end)}",
                    "per_page": 100,
                    **github_cursor,
                }
                headers = {"Authorization": f"Bearer {settings.github_token}"} if settings.github_token else {}
            response = await request(client, "GET", URLS[source], params=params, headers=headers)
            data = response.json()
            rows = data.get("vulnerabilities", []) if source == "nvd" else data
            if not isinstance(rows, list):
                raise ValueError("Resposta da fonte não é uma lista de advisories")
            for index, raw in enumerate(rows):
                stamp = normalize(source, raw).get(job.basis)
                if stamp is None:
                    raise ValueError("Fonte retornou advisory sem a data solicitada; cobertura incompleta")
                instant = utc_datetime(datetime.fromisoformat(stamp))
                if not utc_datetime(job.since) <= instant <= utc_datetime(job.until):
                    continue
                identifier = normalize(source, raw)["id"]
                existing = session.get(Advisory, f"{source}:{identifier}")
                new_count += existing is None
                updated_count += existing is not None and existing.payload != raw
                targets.add(upsert(session, source, raw).id)
                if index % 50 == 49:
                    await asyncio.sleep(0)
            fetched += len(rows)
            pages += 1
            job.progress = {
                **job.progress,
                "active_source": source,
                "sources": {
                    **job.progress.get("sources", {}),
                    source: {
                        "status": "running",
                        "fetched": fetched,
                        "pages": pages,
                        "new": new_count,
                        "updated": updated_count,
                        "upstream_total": data.get("totalResults") if source == "nvd" else None,
                    },
                },
                "pages": job.progress.get("pages", 0) + 1,
                "fetched": job.progress.get("fetched", 0) + len(rows),
            }
            session.commit()  # Advisory page and its progress are one durable transaction.
            page += 1
            if source == "github":
                github_cursor = github_next_page(response, seen_github_cursors)
            complete = page * 2000 >= data.get("totalResults", 0) if source == "nvd" else github_cursor is None
            if complete:
                break
            if pages >= 500:
                raise ValueError("Limite de páginas atingido; divida o intervalo")
            await asyncio.sleep((0.75 if settings.nvd_api_key else 6.5) if source == "nvd" else 0.25)
        start = window_end
        if start < end:
            await asyncio.sleep(0.75 if settings.nvd_api_key else 6.5)
    return {"status": "success", "fetched": fetched, "pages": pages, "new": new_count, "updated": updated_count}


async def enrich_source(session, job, source, client, targets):
    count, pages = 0, 0
    if source == "kev":
        rows = (await fetch_kev(client))["vulnerabilities"]
        for raw in rows:
            alias = session.get(Alias, raw["cveID"])
            if alias is None or alias.vulnerability_id not in targets:
                continue
            vulnerability = session.get(Vulnerability, alias.vulnerability_id)
            if not vulnerability.kev:
                session.add(Activity(kind="exploitation.updated", subject=vulnerability.id, data={"source": "kev", "from": False, "to": True, "date_added": raw.get("dateAdded")}))
            vulnerability.kev = True
            advisory = session.get(Advisory, "kev:" + raw["cveID"])
            if advisory:
                advisory.payload = raw
            else:
                session.add(Advisory(id="kev:" + raw["cveID"], vulnerability_id=vulnerability.id, source="kev", payload=raw))
            count += 1
        pages = 1
        session.commit()
    else:
        aliases = []
        identifiers = list(targets)
        for start in range(0, len(identifiers), 1000):
            aliases.extend(session.scalars(select(Alias.id).where(Alias.vulnerability_id.in_(identifiers[start : start + 1000]), Alias.id.like("CVE-%"))))
        for index in range(0, len(aliases), 100):
            rows = (await request(client, "GET", URLS["epss"], params={"cve": ",".join(aliases[index : index + 100])})).json()["data"]
            for raw in rows:
                alias = session.get(Alias, raw["cve"])
                vulnerability = session.get(Vulnerability, alias.vulnerability_id)
                if vulnerability.epss != float(raw["epss"]):
                    session.add(Activity(kind="epss", subject=vulnerability.id, data=raw))
                vulnerability.epss = float(raw["epss"])
                count += 1
            pages += 1
            job.progress = {**job.progress, "sources": {**job.progress["sources"], source: {"status": "running", "fetched": count, "pages": pages}}}
            session.commit()
    return {"status": "success", "fetched": count, "pages": pages}


async def run_collection(identifier):
    from .workers import sync_lock

    try:
        async with sync_lock:
            with Session() as session:
                job = session.get(RadarCollection, identifier)
                if not job or job.status == "cancelled":
                    return
                job.status = "running"
                session.commit()
                targets = set()
                async with httpx.AsyncClient(timeout=45, headers={"User-Agent": "VulnRadar-period-radar/1"}) as client:
                    for source in ["nvd", "github", "kev", "epss"] if job.enrich else ["nvd", "github"]:
                        job.progress = {
                            **job.progress,
                            "active_source": source,
                            "sources": {**job.progress.get("sources", {}), source: {"status": "running", "fetched": 0, "pages": 0}},
                        }
                        session.commit()
                        try:
                            result = await (
                                collect_source(session, job, source, client, targets) if source in {"nvd", "github"} else enrich_source(session, job, source, client, targets)
                            )
                        except Exception as exc:
                            session.rollback()
                            job = session.get(RadarCollection, identifier)
                            previous = job.progress.get("sources", {}).get(source, {})
                            result = {
                                **previous,
                                "status": "partial" if previous.get("pages") else "failed",
                                "error": f"{type(exc).__name__}: fonte incompleta; resultados anteriores preservados",
                            }
                        job.progress = {**job.progress, "sources": {**job.progress.get("sources", {}), source: result}}
                        if result.get("pages") or result["status"] != "success":
                            state = session.get(Source, source)
                            if state is None:
                                state = Source(id=source)
                                session.add(state)
                            state.status, state.last_run = result["status"], now().isoformat()
                            state.count, state.error = result.get("fetched", 0), result.get("error")
                        session.add(
                            SyncRun(
                                source=source,
                                status=result["status"],
                                started_at=job.created_at,
                                completed_at=now(),
                                processed_count=result.get("fetched", 0),
                                new_count=result.get("new", 0),
                                updated_count=result.get("updated", 0),
                                pages=result.get("pages", 0),
                                error=result.get("error"),
                            )
                        )
                        session.commit()
                statuses = [value["status"] for value in job.progress["sources"].values()]
                primary = [job.progress["sources"][source]["status"] for source in ("nvd", "github")]
                job.status = "success" if all(value == "success" for value in statuses) else "failed" if all(value == "failed" for value in primary) else "partial"
                job.completed_at = now()
                session.add(
                    Activity(
                        kind="radar.collection",
                        subject=str(job.id),
                        data={"status": job.status, "since": utc_datetime(job.since).isoformat(), "until": utc_datetime(job.until).isoformat(), "basis": job.basis},
                    )
                )
                session.commit()
    except asyncio.CancelledError:
        with Session() as session:
            job = session.get(RadarCollection, identifier)
            if job:
                job.status, job.completed_at = "cancelled", now()
                job.progress = {**job.progress, "error": "Coleta cancelada; páginas já salvas foram preservadas"}
                session.commit()
        raise
    except Exception as exc:
        with Session() as session:
            job = session.get(RadarCollection, identifier)
            if job:
                job.status, job.completed_at = "failed", now()
                job.progress = {**job.progress, "error": f"{type(exc).__name__}: coleta interrompida; páginas já salvas preservadas"}
                session.commit()


class QueueInput(BaseModel):
    identifiers: list[str] = Field(min_length=1, max_length=100)


@router.post("/queue")
def queue(body: QueueInput, session: DBSession = Depends(get_session)):
    identifiers = set(body.identifiers)
    rows = list(session.scalars(select(Vulnerability).where(Vulnerability.id.in_(identifiers))))
    if len(rows) != len(identifiers):
        raise HTTPException(404, "Uma das vulnerabilidades não existe na base coletada")
    changed = 0
    for vulnerability in rows:
        if vulnerability.triage == "investigating":
            continue
        session.add(
            Activity(
                kind="triage",
                subject=vulnerability.id,
                data={"from": vulnerability.triage, "to": "investigating", "reason": "Incluída manualmente na fila de investigação do radar"},
            )
        )
        vulnerability.triage = "investigating"
        changed += 1
    session.commit()
    return {"updated": changed}
