import socket
from types import SimpleNamespace
from datetime import datetime, timezone
import httpx
import pytest
from app.config import settings
from app.services.notifications import validate_destination, send_webhook


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/alert",
        "https://127.0.0.1/alert",
        "https://169.254.169.254/alert",
        "https://localhost/alert",
        "https://hooks.example.com:8443/alert",
        "https://user:password@hooks.example.com/alert",
        "https://unapproved.example/alert",
    ],
)
def test_webhook_rejects_unapproved_or_private_destinations(url):
    with pytest.raises(ValueError):
        validate_destination(url, ["hooks.example.com", "localhost", "127.0.0.1", "169.254.169.254"])


async def test_webhook_payload_is_redacted_and_has_stable_delivery_id(monkeypatch):
    monkeypatch.setattr(settings, "webhook_url", "https://hooks.example.com/alert")
    monkeypatch.setattr(settings, "webhook_allowed_hosts", ["hooks.example.com"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))])
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(204)

    event = SimpleNamespace(
        id=42,
        subject="finding:1",
        created_at=datetime.now(timezone.utc),
        data={"reason": "New finding", "project_id": 1, "secret": "SHOULD-NOT-LEAK", "code": "PRIVATE CODE", "path": "/private/path"},
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await send_webhook(event, client)
    assert requests[0].headers["Idempotency-Key"] == "vulnradar-alert-42"
    assert all(value not in requests[0].content.decode() for value in ["SHOULD-NOT-LEAK", "PRIVATE CODE", "/private/path"])


async def test_webhook_rejects_private_dns_and_redirects(monkeypatch):
    monkeypatch.setattr(settings, "webhook_url", "https://hooks.example.com/alert")
    monkeypatch.setattr(settings, "webhook_allowed_hosts", ["hooks.example.com"])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.1.1", 443))])
    event = SimpleNamespace(id=1, subject="fixture", created_at=datetime.now(timezone.utc), data={})
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(302, headers={"Location": "https://unapproved.example"}))) as client:
        with pytest.raises(ValueError):
            await send_webhook(event, client)
        monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))])
        with pytest.raises(httpx.HTTPStatusError):
            await send_webhook(event, client)


async def test_delivery_status_and_retries_are_persisted_without_duplicate_send(session, monkeypatch):
    from sqlalchemy import select, func
    from sqlalchemy.orm import sessionmaker
    from datetime import timedelta
    from app.db import Activity, NotificationDelivery, now
    from app.services import notifications

    monkeypatch.setattr(settings, "webhook_url", "https://hooks.example.com/alert")
    monkeypatch.setattr(notifications, "Session", sessionmaker(session.get_bind(), expire_on_commit=False))
    event = Activity(kind="alert", subject="fixture-only", data={"reason": "Fixture"})
    session.add(event)
    session.commit()

    async def fail(_):
        raise httpx.ConnectError("Test-only transport failure")

    monkeypatch.setattr(notifications, "send_webhook", fail)
    assert await notifications.dispatch_once()
    session.expire_all()
    delivery = session.scalar(select(NotificationDelivery))
    assert delivery.status == "retry" and delivery.attempts == 1
    assert not await notifications.dispatch_once()
    delivery.next_attempt = now() - timedelta(seconds=1)
    session.commit()

    async def success(_):
        pass

    monkeypatch.setattr(notifications, "send_webhook", success)
    assert await notifications.dispatch_once()
    session.expire_all()
    assert delivery.status == "delivered" and delivery.attempts == 2
    assert not await notifications.dispatch_once()
    assert session.scalar(select(func.count()).select_from(NotificationDelivery)) == 1
