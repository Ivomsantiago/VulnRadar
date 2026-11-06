import asyncio
from sqlalchemy import select
from .config import settings
from .db import Activity, Project, Scan, Session, Watch, now
from .security import authorized_path
from .services.scanner import sca, sast
from .services.monitoring import check_watch
from .services.intelligence import sync_source


sync_lock = asyncio.Lock()


scan_lock = asyncio.Lock()


jobs = set()


def spawn(coro):
    task = asyncio.create_task(coro)
    jobs.add(task)
    task.add_done_callback(jobs.discard)
    return task


async def run_scan(scan_id):
    async with scan_lock:
        with Session() as session:
            scan = session.get(Scan, scan_id)
            project = session.get(Project, scan.project_id)
            scan.status = "running"
            session.commit()
            try:
                root = authorized_path(project.path)
                async with asyncio.timeout(settings.scan_timeout):
                    scan.result = await (sca(root) if scan.kind == "sca" else sast(root))
                scan.status = "partial" if scan.result.get("warnings") else "completed"
            except asyncio.CancelledError:
                scan.status = "cancelled"
                scan.result = {"warnings": ["Execução interrompida pelo encerramento do serviço"]}
                raise
            except Exception as exc:
                scan.status = "failed"
                scan.result = {"warnings": [f"{type(exc).__name__}: análise não concluída"], "findings": []}
            finally:
                scan.completed_at = now()
                session.add(Activity(kind="scan", subject=str(scan_id), data={"status": scan.status}))
                session.commit()


async def run_sync(source):
    async with sync_lock:
        with Session() as session:
            await sync_source(session, source)


async def periodic():
    while True:
        for source in ("nvd", "github", "kev", "epss"):
            await run_sync(source)
        with Session() as session:
            identifiers = list(session.scalars(select(Watch.id).where(Watch.version.is_not(None))))
            for identifier in identifiers:
                try:
                    await check_watch(session, identifier)
                except Exception as exc:
                    session.rollback()
                    session.add(Activity(kind="watch.failed", subject=str(identifier), data={"error_type": type(exc).__name__}))
                    session.commit()
        await asyncio.sleep(max(settings.sync_minutes, 5) * 60)
