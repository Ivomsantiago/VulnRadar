"""Central HTTP boundary: authentication, authorization, budgets and safe errors."""
import asyncio
import hashlib
import ipaddress
from collections.abc import Awaitable, Callable
from uuid import uuid4

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from .access import budget, current_principal, permitted
from .config import settings
from .logging import logger
from .security_context import actor, request_id

inflight_expensive = 0


def rejected(status: int, detail: str) -> JSONResponse:
    response = JSONResponse({"detail": detail}, status_code=status)
    if status == 429:
        response.headers["Retry-After"] = "60"
    return response


def local_peer(request: Request) -> bool:
    try:
        return ipaddress.ip_address(request.client.host if request.client else "").is_loopback
    except ValueError:
        return False


async def dispatch(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    global inflight_expensive
    path, method = request.url.path, request.method
    if settings.access_mode == "local" and not local_peer(request):
        return rejected(403, "Modo local aceita somente conexões loopback")
    if request.headers.get("host", "").split(":")[0] not in settings.allowed_hosts and request.url.hostname not in settings.allowed_hosts:
        return rejected(400, "Host não autorizado")
    health_probe = path in {"/api/health", "/api/ready", "/health", "/ready"} and local_peer(request)
    if settings.access_mode == "team" and request.url.scheme != "https" and not health_probe:
        return rejected(403, "Modo de equipe exige HTTPS")
    origin = request.headers.get("origin")
    if (origin and origin not in settings.origins) or request.headers.get("sec-fetch-site") == "cross-site":
        return rejected(403, "Origem não autorizada")
    if method not in {"GET", "HEAD", "OPTIONS"} and request.headers.get("X-VulnRadar-Client") != "web":
        return rejected(403, "Cabeçalho de cliente obrigatório")
    if method in {"POST", "PATCH", "PUT"} and (request.headers.get("content-length", "0") != "0" or "transfer-encoding" in request.headers):
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
            return rejected(415, "Envie o corpo como application/json")
    if method == "OPTIONS":
        return await call_next(request)
    protected = path.startswith("/api/") or path in {"/docs", "/openapi.json", "/redoc"}
    principal = current_principal(request)
    if settings.access_mode == "team" and not settings.access_keys:
        return rejected(503, "Controle de acesso não configurado")
    request.state.principal = principal
    public = path in {"/api/health", "/api/ready", "/health", "/ready", "/api/auth/session", "/api/auth/login"}
    if protected and not public:
        if principal is None:
            return rejected(401, "Autenticação necessária")
        if path != "/api/auth/logout" and not permitted(principal.role, method, path):
            logger.warning("access.denied")
            return rejected(403, "Perfil sem permissão para esta operação")
    identity = principal.name if principal else hashlib.sha256((request.client.host if request.client else "unknown").encode()).hexdigest()
    if path == "/api/auth/login" and not budget(identity, "login", 5):
        return rejected(429, "Muitas tentativas; aguarde um minuto")
    if protected and not budget(identity, "requests", settings.requests_per_minute):
        return rejected(429, "Limite de requisições atingido; aguarde um minuto")
    if protected and method not in {"GET", "HEAD"} and not budget(identity, "mutations", settings.mutations_per_minute):
        return rejected(429, "Limite de operações atingido; aguarde um minuto")
    token = actor.set(principal.name if principal else "anonymous")
    expensive = path == "/api/search/package" or "/imports/" in path or path.startswith("/api/reports/") or path.endswith("/export") or path == "/api/export"
    if expensive and inflight_expensive >= 4:
        actor.reset(token)
        return rejected(429, "Há operações de consulta/importação em andamento; aguarde")
    if expensive:
        inflight_expensive += 1
    try:
        if path == "/api/events":
            return await call_next(request)
        async with asyncio.timeout(settings.request_timeout):
            return await call_next(request)
    finally:
        if expensive:
            inflight_expensive -= 1
        actor.reset(token)


async def security_boundary(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    identifier = uuid4().hex
    token = request_id.set(identifier)
    try:
        try:
            response = await dispatch(request, call_next)
        except TimeoutError:
            logger.warning("http.timeout")
            response = rejected(504, "Operação excedeu o prazo; consulte o histórico antes de reenviar")
        except Exception as exc:
            logger.error("http.failed", extra={"fields": {"error_type": type(exc).__name__}})
            response = rejected(500, "Falha interna; informe o identificador da requisição ao administrador")
        response.headers["X-Request-ID"] = identifier
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if settings.access_mode == "team" and request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response
    finally:
        request_id.reset(token)
