"""Single-workspace access keys and opaque, bounded, revocable browser sessions.

Keys must be randomly generated 256-bit secrets, not human passwords. Only their
SHA256 digest is configured. No token, cookie or IP address is persisted in logs.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import re
import secrets
import time

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from .config import settings
from .logging import logger

COOKIE = "vr_session"
router = APIRouter(prefix="/api/auth", tags=["Access"])


@dataclass(frozen=True)
class Principal:
    name: str
    role: str
    key_digest: str


@dataclass
class BrowserSession:
    principal: Principal
    created: float
    seen: float


sessions: dict[str, BrowserSession] = {}
buckets: dict[tuple[str, str], tuple[float, int]] = {}
stream_counts: dict[str, int] = {}


def budget(identity: str, category: str, limit: int) -> bool:
    tick = time.monotonic()
    key = (identity, category)
    if len(buckets) > 4096:
        for old, (began, _) in list(buckets.items()):
            if tick - began >= 60:
                buckets.pop(old, None)
        if len(buckets) > 4096 and key not in buckets:
            return False
    began, count = buckets.get(key, (tick, 0))
    if tick - began >= 60:
        began, count = tick, 0
    buckets[key] = (began, count + 1)
    return count < limit


def key_principal(secret: str) -> Principal | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", secret):
        return None
    digest = hashlib.sha256(secret.encode()).hexdigest()
    result = None
    for name, key in settings.access_keys.items():
        if hmac.compare_digest(digest, key.digest) and key.expires_at > datetime.now(timezone.utc):
            result = Principal(name, key.role, digest)
    return result


def current_principal(request: Request) -> Principal | None:
    authorization = request.headers.get("authorization")
    if authorization is not None:
        scheme, _, value = authorization.partition(" ")
        return key_principal(value) if scheme.lower() == "bearer" else None
    token = request.cookies.get(COOKIE, "")
    if len(token) != 43:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    stored = sessions.get(digest)
    if stored is None:
        return None
    tick = time.monotonic()
    key = settings.access_keys.get(stored.principal.name)
    valid = (key is not None and hmac.compare_digest(key.digest, stored.principal.key_digest)
             and key.role == stored.principal.role and key.expires_at > datetime.now(timezone.utc)
             and tick - stored.created < settings.session_minutes * 60
             and tick - stored.seen < settings.session_idle_minutes * 60)
    if not valid:
        sessions.pop(digest, None)
        return None
    stored.seen = tick
    return stored.principal


READ_ROUTES = (
    r"/api/(dashboard|sources|intelligence/quality|watchlist|projects|scans|activity|inventory|exposure|technologies|search/universal|sync-runs|preferences|finding-trend|scheduler|notification-deliveries|products|product-watches|export|events)",
    r"/api/vulnerabilities(?:/[^/]+)?", r"/api/findings(?:/\d+)?",
    r"/api/findings/\d+/vex",
    r"/api/scans/\d+(?:/export)?", r"/api/reports/(findings|exposure)",
)
ANALYST_READ = (r"/api/projects/\d+/inspect", r"/api/(directories|engines)")
ANALYST_WRITE = (
    r"/api/(findings|vulnerabilities)/[^/]+/triage",
    r"/api/(watchlist|product-watches)(?:/\d+(?:/check)?)?",
    r"/api/projects/\d+/scans/(sca|sast|combined)", r"/api/scans/\d+/cancel",
    r"/api/search/package",
    r"/api/projects/\d+/imports/sarif",
    r"/api/findings/\d+/vex",
)


def permitted(role: str, method: str, path: str) -> bool:
    if role == "admin":
        return True
    if method in {"GET", "HEAD"}:
        patterns = READ_ROUTES + (ANALYST_READ if role == "analyst" else ())
        return any(re.fullmatch(pattern, path) for pattern in patterns)
    return role == "analyst" and any(re.fullmatch(pattern, path) for pattern in ANALYST_WRITE)


class LoginInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access_key: SecretStr = Field(min_length=43, max_length=43)


@router.get("/session")
def session_state(request: Request) -> dict[str, object]:
    principal = getattr(request.state, "principal", None)
    return {"authentication_required": True,
            "principal": {"name": principal.name, "role": principal.role} if principal else None,
            "workspace_scope": "Um workspace compartilhado; sem isolamento entre organizações"}


@router.post("/login")
def login(body: LoginInput, request: Request, response: Response) -> dict[str, str]:
    principal = key_principal(body.access_key.get_secret_value())
    if principal is None:
        logger.warning("auth.failed")
        raise HTTPException(401, "Chave inválida ou expirada")
    tick = time.monotonic()
    for digest, old in list(sessions.items()):
        if tick - old.created >= settings.session_minutes * 60 or tick - old.seen >= settings.session_idle_minutes * 60:
            sessions.pop(digest, None)
    if len(sessions) >= settings.max_sessions:
        raise HTTPException(429, "Limite de sessões atingido; aguarde expiração ou encerre uma sessão")
    old_token = request.cookies.get(COOKIE, "")
    sessions.pop(hashlib.sha256(old_token.encode()).hexdigest(), None)
    token = secrets.token_urlsafe(32)
    sessions[hashlib.sha256(token.encode()).hexdigest()] = BrowserSession(principal, tick, tick)
    response.set_cookie(COOKIE, token, httponly=True, secure=settings.access_mode == "team", samesite="strict", path="/", max_age=settings.session_minutes * 60)
    logger.info("auth.succeeded", extra={"fields": {"actor": principal.name}})
    return {"name": principal.name, "role": principal.role}


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response) -> None:
    token = request.cookies.get(COOKIE, "")
    sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)
    response.delete_cookie(COOKIE, path="/", secure=settings.access_mode == "team", httponly=True, samesite="strict")
    logger.info("auth.logout")
