from datetime import timedelta
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker
from app.config import settings
from app.db import Activity, NotificationDelivery, now
from app.services.retention import apply_retention


async def test_retention_preserves_audit_and_does_not_requeue_removed_deliveries(session, monkeypatch):
    from app.services import notifications
    monkeypatch.setattr(settings, "retention_progress_days", 7)
    monkeypatch.setattr(settings, "retention_delivery_days", 7)
    old = now() - timedelta(days=30)
    progress = Activity(kind="scan.progress", subject="1", created_at=old)
    triage = Activity(kind="finding.triage", subject="finding:1", created_at=old)
    alert = Activity(kind="alert", subject="test-only", created_at=old)
    session.add_all([progress, triage, alert])
    session.flush()
    session.add(NotificationDelivery(activity_id=alert.id, status="delivered", last_attempt=old))
    session.commit()
    assert apply_retention(session)["progress_events"] == 1
    assert session.get(Activity, progress.id) is not None
    result = apply_retention(session, dry_run=False)
    assert result["notification_records"] == 1
    session.expire_all()
    assert session.get(Activity, triage.id) is not None
    assert list(session.scalars(select(NotificationDelivery))) == []
    monkeypatch.setattr(settings, "webhook_url", "https://configured.example.test")
    monkeypatch.setattr(notifications, "Session", sessionmaker(session.get_bind(), expire_on_commit=False))
    assert await notifications.dispatch_once() is False
