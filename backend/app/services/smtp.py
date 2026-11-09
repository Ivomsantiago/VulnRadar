"""Optional SMTP over implicit TLS, with minimal message content and stable IDs."""
import asyncio
from email.message import EmailMessage
import smtplib
import ssl
from ..config import settings


async def send_smtp(event):
    if not settings.smtp_host or settings.smtp_host not in settings.smtp_allowed_hosts or not settings.smtp_sender or not settings.smtp_recipients:
        raise ValueError("SMTP não configurado com destino autorizado")
    message = EmailMessage()
    message["From"] = settings.smtp_sender
    message["To"] = ", ".join(settings.smtp_recipients)
    message["Subject"] = f"VulnRadar: alerta #{event.id}"
    message["Message-ID"] = f"<vulnradar-alert-{event.id}@local.invalid>"
    message["X-VulnRadar-Idempotency-Key"] = f"vulnradar-alert-{event.id}"
    message.set_content(f"Alerta #{event.id} disponível no VulnRadar. Consulte a aplicação autenticada para investigar.\nEsta mensagem não contém código, nomes de pacotes, caminhos, responsáveis ou justificativas de triagem.")

    def send():
        with smtplib.SMTP_SSL(settings.smtp_host, port=465, timeout=10, context=ssl.create_default_context()) as connection:
            if settings.smtp_username and settings.smtp_password:
                connection.login(settings.smtp_username, settings.smtp_password.get_secret_value())
            connection.send_message(message)

    await asyncio.to_thread(send)
