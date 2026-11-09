"""Optional retention of transient progress and terminal delivery metadata only."""
from datetime import datetime, timedelta
from sqlalchemy import delete, func, select
from ..config import settings
from ..db import Activity, NotificationDelivery, PlatformSetting, now, utc_datetime


def apply_retention(session, dry_run=True):
    progress = None
    deliveries = None
    cutoff = now() - timedelta(days=settings.retention_delivery_days)
    if settings.retention_progress_days:
        progress = select(Activity.id).where(Activity.kind == "scan.progress", Activity.created_at < now() - timedelta(days=settings.retention_progress_days), Activity.id.not_in(select(NotificationDelivery.activity_id)))
    if settings.retention_delivery_days:
        deliveries = select(NotificationDelivery.id).where(NotificationDelivery.status.in_(["delivered", "failed"]), NotificationDelivery.last_attempt < cutoff)
    result = {"dry_run": dry_run, "progress_events": session.scalar(select(func.count()).select_from(progress.subquery())) if progress is not None else 0,
              "notification_records": session.scalar(select(func.count()).select_from(deliveries.subquery())) if deliveries is not None else 0,
              "preserved": "Scans, inventários, achados, observações, triagem, VEX e histórico de estados são preservados"}
    if dry_run:
        return result
    if progress is not None:
        session.execute(delete(Activity).where(Activity.id.in_(progress)))
    if deliveries is not None and result["notification_records"]:
        floor = session.get(PlatformSetting, "notifications.retention_floor")
        value = max(utc_datetime(datetime.fromisoformat(floor.value["at"])), cutoff) if floor else cutoff
        if floor:
            floor.value = {"at": value.isoformat()}
        else:
            session.add(PlatformSetting(key="notifications.retention_floor", value={"at": value.isoformat()}))
        session.execute(delete(NotificationDelivery).where(NotificationDelivery.id.in_(deliveries)))
    session.add(Activity(kind="retention.applied", subject="platform", data=result))
    session.commit()
    return result


def maintain_retention(session):
    if not (settings.retention_progress_days or settings.retention_delivery_days):
        return
    last = session.get(PlatformSetting, "retention.last_run")
    if last and now() - utc_datetime(datetime.fromisoformat(last.value["at"])) < timedelta(days=1):
        return
    apply_retention(session, dry_run=False)
    if last:
        last.value = {"at": now().isoformat()}
    else:
        session.add(PlatformSetting(key="retention.last_run", value={"at": now().isoformat()}))
    session.commit()
