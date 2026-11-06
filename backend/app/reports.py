"""Reports use the same filtered finding set for preview and export."""

import csv
import io
from datetime import datetime
from fastapi import APIRouter, Depends, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .db import Finding, Project, Scan, get_session, now, utc_datetime
from .services.findings import CLOSED

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.get("/findings")
def report(
    project_id: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    kind: str | None = None,
    technology: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    format: str = Query("json", pattern="^(json|csv)$"),
    session: Session = Depends(get_session),
):
    since = utc_datetime(since) if since else None
    until = utc_datetime(until) if until else None
    stmt = select(Finding, Project.name).join(Project, Finding.project_id == Project.id)
    for column, value in ((Finding.project_id, project_id), (Finding.severity, severity), (Finding.status, status), (Finding.kind, kind)):
        if value is not None:
            stmt = stmt.where(column == value)
    if technology:
        stmt = stmt.where(Finding.package.ilike(f"%{technology}%"))
    if since:
        stmt = stmt.where(Finding.first_seen >= since)
    if until:
        stmt = stmt.where(Finding.first_seen <= until)
    count = session.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = session.execute(stmt.order_by(Finding.first_seen.desc(), Finding.id).limit(5000)).all()
    items = [
        {
            "id": f.id,
            "project": project,
            "project_id": f.project_id,
            "kind": f.kind,
            "vulnerability": f.vulnerability_id,
            "rule": f.rule_id,
            "component": f.package,
            "version": f.version,
            "fixed_versions": f.fixed_versions,
            "severity": f.severity,
            "status": f.status,
            "owner": f.owner,
            "due_at": f.due_at,
            "risk_expires_at": f.risk_expires_at,
            "remediation_plan": f.remediation_plan,
            "first_seen": f.first_seen,
            "last_seen": f.last_seen,
            "overdue": bool(f.due_at and utc_datetime(f.due_at) < now() and f.status not in CLOSED),
        }
        for f, project in rows
    ]
    # Coverage has its own scope; severity/triage filters do not apply to executions.
    scans = select(Scan)
    if project_id:
        scans = scans.where(Scan.project_id == project_id)
    if since:
        scans = scans.where(Scan.created_at >= since)
    if until:
        scans = scans.where(Scan.created_at <= until)
    if kind:
        scans = scans.where(Scan.kind.in_([kind, "combined"]))
    coverage = dict(session.execute(select(Scan.status, func.count()).where(Scan.id.in_(scans.with_only_columns(Scan.id))).group_by(Scan.status)).all())
    payload = {
        "generated_at": now(),
        "total": count,
        "exported": len(items),
        "truncated": count > len(items),
        "items": items,
        "coverage": coverage,
        "scope": "Achados por primeira observação; estado atual de remediação. Cobertura por projeto/período/motor, independente de severidade e status de achados.",
    }
    if format == "json":
        return payload
    output = io.StringIO()
    fields = [
        "id",
        "project",
        "kind",
        "vulnerability",
        "rule",
        "component",
        "version",
        "fixed_versions",
        "severity",
        "status",
        "owner",
        "due_at",
        "risk_expires_at",
        "remediation_plan",
        "first_seen",
        "overdue",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in jsonable_encoder(items):
        writer.writerow({key: "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value for key, value in row.items()})
    return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=vulnradar-findings.csv"})
