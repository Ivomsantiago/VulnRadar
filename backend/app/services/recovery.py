"""Interrupted work is failed explicitly, preserving payloads and checkpoints."""
from sqlalchemy import select
from ..db import Activity, Scan, Source, SyncRun, now


def recover_interrupted(session):
    message = "Execução interrompida pelo reinício; reenvie a operação. Não há conclusão de segurança."
    for scan in session.scalars(select(Scan).where(Scan.status.in_(["running", "pending"]))):
        scan.status = scan.stage = "failed"
        scan.completed_at = now()
        scan.result = {**scan.result, "warnings": [*scan.result.get("warnings", []), message]}
        session.add(Activity(kind="job.interrupted", subject=f"scan:{scan.id}", data={"status": "failed"}))
    for source in session.scalars(select(Source).where(Source.status == "running")):
        source.status, source.error = "failed", message
    for run in session.scalars(select(SyncRun).where(SyncRun.status == "running")):
        run.status, run.error, run.completed_at = "failed", message, now()
    session.commit()
