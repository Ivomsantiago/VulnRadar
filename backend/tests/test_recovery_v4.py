from sqlalchemy import select
from app.db import Project, Scan, Source, SyncRun
from app.services.recovery import recover_interrupted


def test_restart_preserves_scan_payload_and_source_checkpoint(session):
    project = Project(name="Recovery fixture", path="/fixture")
    session.add(project)
    session.flush()
    scan = Scan(project_id=project.id, kind="sca", status="running", result={"request": {"fixture": True}, "warnings": ["original warning"]})
    source = Source(id="nvd", status="running", checkpoint="2026-01-01T00:00:00Z")
    run = SyncRun(source="nvd", status="running", processed_count=12, pages=2)
    session.add_all([scan, source, run])
    session.commit()
    recover_interrupted(session)
    assert scan.status == scan.stage == "failed" and scan.result["request"] == {"fixture": True}
    assert "original warning" in scan.result["warnings"]
    assert source.status == "failed" and source.checkpoint == "2026-01-01T00:00:00Z"
    assert run.status == "failed" and run.processed_count == 12 and run.pages == 2
    assert session.scalar(select(Scan)).completed_at.tzinfo is not None
