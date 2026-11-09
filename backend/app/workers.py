import asyncio
from sqlalchemy import select
from .config import settings
from .logging import logger
from .db import Activity, Project, Scan, Session, Source, SyncRun, Watch, now
from .security import authorized_path
from .services.scanner import sca, sast
from .services.oci import oci
from .services.findings import index_scan
from .services.monitoring import check_watch
from .services.intelligence import sync_source

sync_lock = asyncio.Lock()
scan_lock = asyncio.Lock()
jobs = set()
scan_tasks = {}


async def supervise(name, runner):
    while True:
        try:
            await runner()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error("worker.restarting", extra={"fields": {"stage": name, "error_type": type(exc).__name__}})
        await asyncio.sleep(5)


def spawn(coro):
    task = asyncio.create_task(coro)
    jobs.add(task)
    task.add_done_callback(jobs.discard)
    return task


def queue_scan(scan_id):
    task = spawn(run_scan(scan_id))
    scan_tasks[scan_id] = task
    task.add_done_callback(lambda _: scan_tasks.pop(scan_id, None))
    return task


async def run_scan(scan_id):
    try:
        async with scan_lock:
            with Session() as session:
                scan = session.get(Scan, scan_id)
                if scan.status == "cancelled":
                    return
                project = session.get(Project, scan.project_id)
                scan.status, scan.stage = "running", "preparing"
                session.commit()

                async def progress(stage):
                    logger.info("scan.progress", extra={"fields": {"scan_id": scan_id, "stage": stage}})
                    scan.stage = stage
                    session.commit()
                    session.add(Activity(kind="scan.progress", subject=str(scan_id), data={"stage": stage}))
                    session.commit()

                try:
                    root = authorized_path(project.path)
                    async with asyncio.timeout(settings.oci_timeout if scan.kind == "oci" else settings.scan_timeout):
                        if scan.kind == "combined":
                            results = {}
                            for kind, runner in (("sca", sca), ("sast", sast)):
                                try:
                                    results[kind] = await runner(root, progress)
                                except Exception as exc:
                                    results[kind] = {"findings": [], "warnings": [f"{kind.upper()}: {type(exc).__name__}; mecanismo não concluído"], "coverage": "failed"}
                            scan.result = {
                                **results,
                                "inventory": results["sca"].get("inventory", []),
                                "findings": results["sca"].get("findings", []) + results["sast"].get("findings", []),
                                "warnings": results["sca"].get("warnings", []) + results["sast"].get("warnings", []),
                                "coverage": "partial" if any(r.get("warnings") for r in results.values()) else "complete",
                            }
                        elif scan.kind == "oci":
                            request = scan.result["request"]
                            scan.result = await oci(request["image"], request["engine"], progress)
                        else:
                            scan.result = await (sca(root, progress) if scan.kind == "sca" else sast(root, progress))
                    await progress("consolidating")
                    for finding in scan.result.get("findings", []):
                        finding["application_exposed"] = project.internet_exposed
                    scan.status = "partial" if scan.result.get("warnings") else "completed"
                    index_scan(session, scan)
                    if scan.kind in {"sca", "combined"} and scan.result.get("inventory"):
                        source = session.get(Source, "osv")
                        if source is None:
                            source = Source(id="osv")
                            session.add(source)
                        components = scan.result["inventory"]
                        successful = sum(c.get("query_status") == "complete" for c in components)
                        source.status = "success" if successful == len(components) else "partial" if successful else "failed"
                        source.count = len(scan.result.get("sca", scan.result).get("findings", []))
                        source.last_run = now().isoformat()
                        source.error = None if source.status == "success" else "Consultas incompletas durante SCA"
                        session.add(
                            SyncRun(
                                source="osv",
                                status=source.status,
                                started_at=scan.created_at,
                                completed_at=now(),
                                processed_count=source.count,
                                new_count=0,
                                updated_count=0,
                                pages=0,
                                error=source.error,
                            )
                        )
                except asyncio.CancelledError:
                    scan.status = "cancelled"
                    scan.result = {"warnings": ["Análise cancelada; nenhuma conclusão de segurança"], "findings": []}
                    raise
                except Exception as exc:
                    session.rollback()
                    scan = session.get(Scan, scan_id)
                    scan.status = "failed"
                    scan.result = {"warnings": [f"{type(exc).__name__}: análise não concluída; verifique os pré-requisitos"], "findings": []}
                finally:
                    logger.info("scan.finished", extra={"fields": {"scan_id": scan_id, "status": scan.status}})
                    scan.stage = scan.status
                    scan.completed_at = now()
                    session.add(Activity(kind="scan", subject=str(scan_id), data={"status": scan.status, "project_id": scan.project_id}))
                    session.commit()
    except asyncio.CancelledError:
        # Cancellation while waiting for a slot must be persisted too.
        with Session() as session:
            scan = session.get(Scan, scan_id)
            if scan and scan.status in {"pending", "running"}:
                scan.status = scan.stage = "cancelled"
                scan.completed_at = now()
                session.add(Activity(kind="scan", subject=str(scan_id), data={"status": "cancelled", "project_id": scan.project_id}))
                session.commit()
        raise


async def run_sync(source):
    async with sync_lock:
        with Session() as session:
            await sync_source(session, source)


async def periodic():
    while True:
        for source in ("nvd", "github", "kev", "epss"):
            await run_sync(source)
        with Session() as session:
            for identifier in list(session.scalars(select(Watch.id))):
                try:
                    await check_watch(session, identifier)
                except Exception as exc:
                    session.rollback()
                    session.add(Activity(kind="watch.failed", subject=str(identifier), data={"error_type": type(exc).__name__}))
                    session.commit()
        await asyncio.sleep(max(settings.sync_minutes, 5) * 60)


async def scheduler_loop():
    from datetime import datetime, timezone
    from .db import PlatformSetting

    while True:
        with Session() as session:
            from .services.history import expire_risks
            from .services.retention import maintain_retention
            expire_risks(session)
            maintain_retention(session)
            row = session.get(PlatformSetting, "scheduler")
            config = row.value if row else {"enabled": settings.auto_sync, "interval_minutes": max(5, settings.sync_minutes)}
            last = datetime.fromisoformat(config["last_started"]) if config.get("last_started") else None
            due = config.get("enabled", False) and (last is None or (datetime.now(timezone.utc) - last).total_seconds() >= config.get("interval_minutes", 60) * 60)
            if due and not sync_lock.locked():
                payload = {**config, "last_started": now().isoformat()}
                if row:
                    row.value = payload
                else:
                    session.add(PlatformSetting(key="scheduler", value=payload))
                session.commit()
        if due and not sync_lock.locked():
            for source in ("nvd", "github", "kev", "epss"):
                await run_sync(source)
            with Session() as session:
                for identifier in list(session.scalars(select(Watch.id))):
                    try:
                        await check_watch(session, identifier)
                    except Exception as exc:
                        session.rollback()
                        session.add(Activity(kind="watch.failed", subject=str(identifier), data={"error_type": type(exc).__name__}))
                        session.commit()
        await asyncio.sleep(5)
