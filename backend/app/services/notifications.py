"""Opt-in webhooks: configured destinations only; no credentials in payload or logs."""

import asyncio
from datetime import timedelta
import ipaddress
import socket
from urllib.parse import urlsplit
import httpx
from sqlalchemy import or_, select
from ..config import settings
from ..db import Activity, NotificationDelivery, Session, now


def validate_destination(url, allowed_hosts):
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or parsed.port not in {None, 443} or host not in allowed_hosts:
        raise ValueError("Webhook exige HTTPS e hostname explicitamente autorizado pela instalação")
    if host in {"localhost", "metadata.google.internal"} or host.endswith((".local", ".internal", ".localhost")):
        raise ValueError("Destino privado não permitido")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if not address.is_global:
        raise ValueError("Endereço privado não permitido")
    return host


async def send_webhook(event, client=None):
    host = validate_destination(settings.webhook_url, settings.webhook_allowed_hosts)
    addresses = await asyncio.to_thread(socket.getaddrinfo, host, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError("DNS do destino não é público")
    # Payload whitelist excludes arbitrary tool evidence, code, local paths and credentials.
    payload = {
        "id": event.id,
        "event": "vulnradar.alert",
        "subject": event.subject,
        "created_at": event.created_at.isoformat(),
        "reason": str(event.data.get("reason", "Alerta VulnRadar")),
        "project_id": event.data.get("project_id"),
        "vulnerability": event.data.get("vulnerability"),
    }
    if settings.webhook_format in {"slack", "teams"}:
        text = f"VulnRadar: {payload['reason']} · {payload['subject']}"
        payload = {"text": text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")}

    async def send(connection):
        response = await connection.post(settings.webhook_url, json=payload, headers={"Idempotency-Key": f"vulnradar-alert-{event.id}"}, follow_redirects=False)
        response.raise_for_status()

    if client is not None:
        await send(client)
    else:
        async with httpx.AsyncClient(timeout=10) as connection:
            await send(connection)


async def dispatch_once():
    if not settings.webhook_url:
        return False
    with Session() as session:
        sent = select(NotificationDelivery.activity_id)
        for identifier in session.scalars(select(Activity.id).where(Activity.kind == "alert", Activity.id.not_in(sent)).order_by(Activity.id).limit(100)):
            session.add(NotificationDelivery(activity_id=identifier))
        session.commit()
        delivery = session.scalar(
            select(NotificationDelivery)
            .where(NotificationDelivery.status.in_(["pending", "retry"]), or_(NotificationDelivery.next_attempt.is_(None), NotificationDelivery.next_attempt <= now()))
            .order_by(NotificationDelivery.id)
            .limit(1)
        )
        if delivery is None:
            return False
        event = session.get(Activity, delivery.activity_id)
        delivery.attempts += 1
        delivery.last_attempt = now()
        try:
            await send_webhook(event)
            delivery.status, delivery.error = "delivered", None
        except (httpx.HTTPError, ValueError, OSError) as exc:
            delivery.status = "failed" if delivery.attempts >= 3 else "retry"
            delivery.error = f"{type(exc).__name__}: entrega não concluída"
            delivery.next_attempt = now() + timedelta(seconds=60 * 2**delivery.attempts)
        session.commit()
        return True


async def notification_loop():
    while True:
        await dispatch_once()
        await asyncio.sleep(max(10, settings.notification_interval_seconds))
