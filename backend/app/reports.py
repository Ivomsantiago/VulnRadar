"""Reports use the same filtered finding set for preview and export."""

import csv
import io
from datetime import datetime, timedelta, timezone, time
from typing import Literal
from fastapi import APIRouter, Depends, Query
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from .db import Finding, FindingState, Project, Scan, PlatformSetting, get_session, now, utc_datetime
from .services.findings import CLOSED
from .services.pdf import report_pdf

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
    change: Literal["all", "new", "resolved", "reopened"] = "all",
    format: str = Query("json", pattern="^(json|csv|pdf)$"),
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
    if change in {"resolved", "reopened"}:
        events = select(FindingState.finding_id).where(FindingState.action == change)
        if since:
            events = events.where(FindingState.occurred_at >= since)
        if until:
            events = events.where(FindingState.occurred_at <= until)
        stmt = stmt.where(Finding.id.in_(events))
    else:
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
        "scope": f"{'Eventos de ' + change if change in {'resolved', 'reopened'} else 'Achados por primeira observação'}; estado atual de remediação. Cobertura por projeto/período/motor, independente de severidade e status de achados.",
    }
    if format == "json":
        return payload
    if format == "pdf":
        lines = [
            f"Gerado em UTC: {now().isoformat()}",
            f"Filtros: projeto={project_id or 'todos'} severidade={severity or 'todas'} estado={status or 'todos'}",
            f"Motor={kind or 'todos'} tecnologia={technology or 'todas'} mudança={change}",
            f"Período: {since or 'sem início'} até {until or 'agora'}",
            f"Total: {count} | Exportados: {len(items)} | Truncado: {'sim' if payload['truncated'] else 'não'}",
            payload["scope"],
            "Cobertura: " + str(coverage),
            "",
        ]
        for item in items:
            lines.extend(
                [
                    f"#{item['id']} {item['project']} | {item['vulnerability'] or item['rule']}",
                    f"{item['kind']} | {item['component'] or 'código'}@{item['version'] or '?'} | {item['severity']} | {item['status']}",
                    f"Responsável: {item['owner'] or 'Não atribuído'} | Prazo: {item['due_at'] or 'Sem prazo'} | Vencido: {'sim' if item['overdue'] else 'não'}",
                    f"Correções informadas: {', '.join(item['fixed_versions']) or 'Não informadas pela fonte'}",
                    f"Plano: {item['remediation_plan'] or 'Não informado'}",
                    "",
                ]
            )
        return Response(
            report_pdf("VulnRadar - Relatório de exposição", lines), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=vulnradar-findings.pdf"}
        )
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


@router.get("/exposure")
def exposure_history(
    days: int = Query(30, ge=1, le=366),
    project_id: int | None = None,
    severity: str | None = None,
    status: str | None = None,
    kind: str | None = None,
    technology: str | None = None,
    format: Literal["json", "csv", "pdf"] = "json",
    session: Session = Depends(get_session),
):
    today = now().date()
    first_day = today - timedelta(days=days - 1)
    statement = select(FindingState).order_by(FindingState.occurred_at, FindingState.id)
    if project_id:
        statement = statement.where(FindingState.project_id == project_id)
    events = list(session.scalars(statement.limit(200001)))
    truncated = len(events) > 200000
    events = events[:200000]
    baseline = session.get(PlatformSetting, "history.started_at")
    baseline_at = datetime.fromisoformat(baseline.value["at"]) if baseline else None
    observed_query = select(func.min(func.coalesce(Scan.completed_at, Scan.created_at))).where(Scan.indexed.is_(True), Scan.status == "completed")
    if project_id:
        observed_query = observed_query.where(Scan.project_id == project_id)
    observed_at = session.scalar(observed_query)
    empty_known_at = max(utc_datetime(baseline_at), utc_datetime(observed_at)) if baseline_at and observed_at else None
    states, index, points = {}, 0, []

    def matches(data):
        return (
            (not severity or data.get("severity") == severity)
            and (not status or data.get("status") == status)
            and (not kind or data.get("kind") == kind)
            and (not technology or technology.casefold() in (data.get("package") or "").casefold())
        )

    for offset in range(days):
        day = first_day + timedelta(days=offset)
        boundary = min(datetime.combine(day, time.max, timezone.utc), now())
        counters = {"new": 0, "resolved": 0, "reopened": 0}
        while index < len(events) and utc_datetime(events[index].occurred_at) <= boundary:
            event = events[index]
            states[event.finding_id] = event.data
            if utc_datetime(event.occurred_at).date() == day and matches(event.data):
                key = "new" if event.action == "created" else event.action
                if key in counters:
                    counters[key] += 1
            index += 1
        selected = [data for data in states.values() if matches(data)]
        known = (bool(states) or (empty_known_at is not None and empty_known_at <= boundary)) and not truncated
        points.append(
            {
                "date": str(day),
                "open": sum(data.get("status") not in CLOSED for data in selected) if known else None,
                "closed": sum(data.get("status") in CLOSED for data in selected) if known else None,
                "overdue": sum(
                    data.get("status") not in CLOSED and data.get("due_at") is not None and utc_datetime(datetime.fromisoformat(data["due_at"])) < boundary for data in selected
                )
                if known
                else None,
                **{key: value if known else None for key, value in counters.items()},
            }
        )
    payload = {
        "items": points,
        "recorded_from": events[0].occurred_at if events else empty_known_at,
        "truncated": truncated,
        "scope": "Estados imutáveis em UTC desde o baseline V3. Sem histórico/análise concluída, o estado permanece desconhecido. Resoluções/reaberturas contam eventos; encerrados incluem decisões de triagem e não comprovam correção técnica. Filtros são aplicados ao estado de cada dia.",
    }
    if format == "json":
        return payload
    fields = ("date", "open", "closed", "overdue", "new", "resolved", "reopened")
    if format == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(points)
        return Response(output.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=exposure-history.csv"})
    lines = [
        payload["scope"],
        f"Início dos registros: {payload['recorded_from'] or 'não registrado'}",
        f"Filtros: projeto={project_id} severidade={severity} estado={status} motor={kind} tecnologia={technology}",
        "Data        Abertos Encerrados Vencidos Novos Resolvidos Reabertos",
    ]
    lines.extend(" | ".join(str(point[key]) if point[key] is not None else "?" for key in fields) for point in points)
    return Response(
        report_pdf("VulnRadar - Histórico de exposição", lines), media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=exposure-history.pdf"}
    )
