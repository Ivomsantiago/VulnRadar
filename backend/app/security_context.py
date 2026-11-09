"""Request identity is server-controlled; background work defaults to system."""
from contextvars import ContextVar

actor: ContextVar[str] = ContextVar("actor", default="system")
request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
