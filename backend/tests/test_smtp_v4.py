from types import SimpleNamespace
import ssl
from pydantic import SecretStr
from app.config import settings
from app.services.smtp import send_smtp


async def test_smtp_uses_verified_tls_minimal_payload_and_stable_identifier(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.test")
    monkeypatch.setattr(settings, "smtp_allowed_hosts", ["smtp.example.test"])
    monkeypatch.setattr(settings, "smtp_sender", "radar@example.test")
    monkeypatch.setattr(settings, "smtp_recipients", ["team@example.test"])
    monkeypatch.setattr(settings, "smtp_username", "radar")
    monkeypatch.setattr(settings, "smtp_password", SecretStr("TEST-ONLY-SECRET"))
    messages = []

    class FakeSMTP:
        def __init__(self, host, port, timeout, context):
            assert host == "smtp.example.test" and port == 465 and timeout == 10
            assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def login(self, username, password):
            assert username == "radar" and password == "TEST-ONLY-SECRET"

        def send_message(self, message):
            messages.append(message)

    monkeypatch.setattr("app.services.smtp.smtplib.SMTP_SSL", FakeSMTP)
    await send_smtp(SimpleNamespace(id=42, subject="PRIVATE-PROJECT", data={"secret": "PRIVATE-DATA"}))
    assert messages[0]["X-VulnRadar-Idempotency-Key"] == "vulnradar-alert-42"
    assert all(value not in messages[0].as_string() for value in ["PRIVATE-PROJECT", "PRIVATE-DATA", "TEST-ONLY-SECRET"])
