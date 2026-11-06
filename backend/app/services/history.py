"""Append-only finding states support honest reports from the first recorded baseline."""

from sqlalchemy import select
from fastapi.encoders import jsonable_encoder
from ..db import Finding, FindingState, PlatformSetting, Activity, now


def record_state(session, finding, action):
    session.add(
        FindingState(
            finding_id=finding.id,
            project_id=finding.project_id,
            occurred_at=now(),
            action=action,
            data=jsonable_encoder(
                {
                    key: getattr(finding, key)
                    for key in (
                        "status",
                        "severity",
                        "kind",
                        "package",
                        "ecosystem",
                        "version",
                        "vulnerability_id",
                        "rule_id",
                        "owner",
                        "due_at",
                        "risk_expires_at",
                        "remediation_plan",
                    )
                }
            ),
        )
    )


def ensure_baseline(session):
    if not session.get(PlatformSetting, "history.started_at"):
        session.add(PlatformSetting(key="history.started_at", value={"at": now().isoformat()}))
    recorded = select(FindingState.finding_id)
    for finding in session.scalars(select(Finding).where(Finding.id.not_in(recorded))):
        record_state(session, finding, "baseline")
    session.commit()


def expire_risks(session):
    for finding in session.scalars(select(Finding).where(Finding.status == "accepted", Finding.risk_expires_at <= now())):
        finding.status = "new"
        record_state(session, finding, "reopened")
        session.add(Activity(kind="finding.reopened", subject=f"finding:{finding.id}", data={"previous_status": "accepted", "reason": "Validade do aceite de risco expirada"}))
        session.add(
            Activity(
                kind="alert", subject=f"finding:{finding.id}:risk-expired", data={"reason": "Aceite de risco expirado", "finding_id": finding.id, "project_id": finding.project_id}
            )
        )
    session.commit()
