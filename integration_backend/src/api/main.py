import logging
import os
import json
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

import time
import urllib.parse
import httpx

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from src.db.config import Base, engine, get_db
from src.db.service import (
    create_user,
    list_users,
    get_user_by_id,
    get_user_by_email,
    upsert_jira_project,
    list_jira_projects_for_user,
    upsert_confluence_page,
    list_confluence_pages_for_user,
)

# Early .env load to support local dev/preview where container env is not injected.
try:
    from dotenv import load_dotenv  # type: ignore
    from pathlib import Path
    # Try a few deterministic locations. Do not override real env variables if already set.
    _env_candidates = [
        os.getenv("INTEGRATION_BACKEND_ENV_FILE"),
        str((Path(__file__).resolve().parents[2] / ".env")),
        str((Path.cwd() / "integration_backend" / ".env")),
    ]
    _loaded = False
    for _p in _env_candidates:
        if _p and os.path.isfile(_p):
            try:
                _loaded = load_dotenv(_p, override=False)
            except Exception:
                _loaded = False
            if _loaded:
                break
    if not _loaded:
        try:
            load_dotenv(override=False)
        except Exception:
            pass
except Exception:
    # dotenv is optional at runtime; if not present or any error occurs, continue gracefully
    pass

from src.api.oauth_config import (
    get_jira_oauth_config,
    get_confluence_oauth_config,
    get_frontend_base_url_default,
    build_atlassian_authorize_url,
    get_jira_oauth_env_debug,
    get_env_bootstrap_debug,
    get_active_redirect_uris_debug,
)
# --- CSRF state helpers ---
import hmac
import hashlib
import secrets

_STATE_COOKIE_NAME = "jira_oauth_state"
_STATE_COOKIE_TTL = 600  # 10 minutes
_STATE_SECRET = os.getenv("STATE_SIGNING_SECRET") or os.getenv("APP_SECRET_KEY") or os.getenv("SECRET_KEY") or "dev-insecure-secret"


def _sign_state(value: str) -> str:
    """Return '<value>.<sig>' where sig = HMAC-SHA256(STATE_SECRET, value)."""
    mac = hmac.new(_STATE_SECRET.encode("utf-8"), msg=value.encode("utf-8"), digestmod=hashlib.sha256)
    return f"{value}.{mac.hexdigest()}"


def _verify_signed_state(signed: str) -> bool:
    """Constant-time verify of signed state; returns True if signature matches."""
    if not signed or "." not in signed:
        return False
    raw, got = signed.rsplit(".", 1)
    mac = hmac.new(_STATE_SECRET.encode("utf-8"), msg=raw.encode("utf-8"), digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), got)


def _gen_csrf_state() -> str:
    """Generate a random opaque state (url-safe)."""
    return secrets.token_urlsafe(24)

from src.api.schemas import (
    UserCreate,
    UserRead,
    JiraProjectCreate,
    JiraProjectRead,
    ConfluencePageCreate,
    ConfluencePageRead,
    ConnectResponse,
    JiraProjectsFetchResponse,
    ConfluencePagesFetchResponse,
    OAuthAuthorizeURL,
)

# -----------------------
# Structured logging setup
# -----------------------


class SafeJSONFormatter(logging.Formatter):
    """A minimal JSON formatter for structured logs with secret redaction support."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now(timezone.utc).isoformat()
        payload: Dict[str, Any] = {
            "timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "event": getattr(record, "event", None),
            "request_id": getattr(record, "request_id", None),
            "provider": getattr(record, "provider", None),
            "path": getattr(record, "path", None),
            "method": getattr(record, "method", None),
            "status_code": getattr(record, "status_code", None),
            "query_params": getattr(record, "query_params", None),
            "headers": getattr(record, "headers", None),
            "extra": getattr(record, "extra", None),
        }

        # Attach exception stacktrace if present
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        # Clean out None values to minimize noise
        cleaned = {k: v for k, v in payload.items() if v is not None}
        try:
            return json.dumps(cleaned, ensure_ascii=False)
        except Exception:
            # Fallback to a simpler log if JSON serialization fails
            return f"{ts} {record.levelname} {record.name} {record.getMessage()}"


def _configure_logging() -> logging.Logger:
    """Initialize application logger with JSON formatter and level from env LOG_LEVEL."""
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    logger = logging.getLogger("integration_backend")
    logger.setLevel(level)

    # Avoid adding multiple handlers on hot reload
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(SafeJSONFormatter())
        logger.addHandler(handler)
        # Prevent propagation to root to avoid duplicate logs with Uvicorn
        logger.propagate = False

    # Tune noisy third-party loggers if necessary
    for noisy in ("httpx", "urllib3"):
        nl = logging.getLogger(noisy)
        if nl.level == logging.NOTSET:
            nl.setLevel(logging.WARNING)

    return logger


APP_LOGGER = _configure_logging()
# Emit a one-time environment bootstrap log for diagnostics
try:
    _bootstrap = get_env_bootstrap_debug()
    APP_LOGGER.info(
        "Environment bootstrap",
        extra={
            "event": "env_bootstrap",
            "dotenv_loaded": _bootstrap.get("dotenv_loaded"),
            "dotenv_path": _bootstrap.get("dotenv_path"),
            "app_env": _bootstrap.get("app_env"),
            "dev_mode": _bootstrap.get("dev_mode"),
        },
    )
except Exception:
    # Non-fatal if diagnostics fail
    pass


# -----------------------
# Helpers for redaction and context extraction
# -----------------------

_SENSITIVE_KEYS = {
    "code",
    "state",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "authorization",
    "cookie",
    "set-cookie",
}


def _redact_value(_: Any) -> str:
    return "***redacted***"


def _should_redact(key: str) -> bool:
    key_lower = key.lower()
    return any(s in key_lower for s in _SENSITIVE_KEYS)


def _redact_mapping(mapping: Dict[str, Any]) -> Dict[str, Any]:
    """Return a redacted copy of a mapping for safe logging."""
    redacted: Dict[str, Any] = {}
    for k, v in mapping.items():
        try:
            if _should_redact(k):
                redacted[k] = _redact_value(v)
            else:
                # ensure primitives for logging
                if isinstance(v, (list, tuple)):
                    redacted[k] = [str(i) for i in v]
                else:
                    redacted[k] = str(v)
        except Exception:
            redacted[k] = "<unloggable>"
    return redacted


def _get_headers_subset(request: Request) -> Dict[str, str]:
    """Extract a safe subset of headers for observability (non-sensitive)."""
    safe_header_names = [
        "user-agent",
        "x-forwarded-for",
        "x-real-ip",
        "cf-connecting-ip",
        "x-request-id",
        "via",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-original-uri",
        "x-scheme",
    ]
    headers = {}
    for name in safe_header_names:
        val = request.headers.get(name)
        if val is not None:
            headers[name] = val
    return headers


def _sanitized_query_params(request: Request) -> Dict[str, Any]:
    """Return a redacted snapshot of query parameters."""
    try:
        # request.query_params is a starlette.datastructures.QueryParams
        raw = dict(request.query_params)
    except Exception:
        raw = {}
    return _redact_mapping(raw)


def _log_event(
    level: int,
    event: str,
    request: Request,
    provider: Optional[str] = None,
    status_code: Optional[int] = None,
    **fields: Any,
) -> None:
    """Centralized structured logging with common request context."""
    rid = getattr(request.state, "request_id", None) or request.headers.get("x-request-id")
    extra = {
        "event": event,
        "request_id": rid,
        "provider": provider,
        "path": str(getattr(request.url, "path", None)),
        "method": getattr(request, "method", None),
        "status_code": status_code,
        "query_params": _sanitized_query_params(request),
        "headers": _get_headers_subset(request),
        "extra": fields or {},
    }
    APP_LOGGER.log(level, event, extra=extra)


# -----------------------
# Middleware: Request ID and unhandled exception logging
# -----------------------

class RequestIDMiddleware(BaseHTTPMiddleware):
    """ASGI middleware to assign/propagate X-Request-ID and echo it in responses."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception as exc:
            # Log and propagate; global handler will sanitize response
            _log_event(logging.ERROR, "unhandled_exception_middleware", request, status_code=500, error=str(exc))
            APP_LOGGER.exception("Unhandled exception in middleware", extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
                "event": "unhandled_exception_middleware",
            })
            raise
        # Echo back request id
        response.headers["X-Request-ID"] = request_id
        return response


openapi_tags = [
    {"name": "Health", "description": "Health and readiness checks."},
    {"name": "Users", "description": "Manage users who connect JIRA/Confluence."},
    {"name": "JIRA Projects", "description": "Manage synced JIRA projects."},
    {"name": "Confluence Pages", "description": "Manage synced Confluence pages."},
    {"name": "Integrations", "description": "Connect and fetch from JIRA/Confluence (placeholders)."},
    {"name": "Auth", "description": "OAuth 2.0 authorization flows for Atlassian (Jira/Confluence)."},
    {"name": "Connectors", "description": "Standardized connector endpoints per provider, mounted at /connectors/{id}."},
]

app = FastAPI(
    title="Jira-Confluence Integration API",
    description="Backend API for integrating JIRA and Confluence, with a lightweight persistence layer.",
    version="0.1.0",
    openapi_tags=openapi_tags,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Ensure RequestID is outermost so all logs include it
app.add_middleware(RequestIDMiddleware)

# CORS setup
allowed_frontend_origin = os.getenv("NEXT_PUBLIC_BACKEND_CORS_ORIGINS", "").split(",")[0].strip() or "https://vscode-internal-36200-beta.beta01.cloud.kavia.ai:3000"
configured = os.getenv("NEXT_PUBLIC_BACKEND_CORS_ORIGINS") or os.getenv("BACKEND_CORS_ORIGINS") or ""
configured_list = [o.strip() for o in configured.split(",")] if configured else []
if allowed_frontend_origin and allowed_frontend_origin not in configured_list:
    configured_list.append(allowed_frontend_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_list if configured_list else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "OPTIONS", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)

# Initialize database tables (for demo; in production, prefer migrations)
Base.metadata.create_all(bind=engine)

# Mount standardized connectors router (Jira/Confluence)
from src.api.routers import connectors as connectors_router  # noqa: E402

app.include_router(connectors_router.router)

# Global unhandled exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Capture any unhandled exception, log it, and return a sanitized 500 with request_id."""
    rid = getattr(request.state, "request_id", None)
    # If this is already a standardized error payload, pass through
    detail = getattr(exc, "detail", None)
    status_code = getattr(exc, "status_code", 500)
    if isinstance(detail, dict) and detail.get("status") == "error":
        return JSONResponse(status_code=status_code, content=detail)

    _log_event(logging.ERROR, "unhandled_exception", request, status_code=500, error=str(exc))
    APP_LOGGER.exception("Unhandled exception", extra={
        "request_id": rid,
        "path": request.url.path,
        "method": request.method,
        "event": "unhandled_exception",
    })
    return JSONResponse(
        status_code=500,
        content={"status": "error", "code": "INTERNAL_ERROR", "message": "Internal Server Error", "request_id": rid},
    )


def _ocean_response(data: Any, message: str = "ok") -> Dict[str, Any]:
    """
    Wrap responses using a simple 'Ocean Professional' style envelope.

    This keeps API responses consistent across endpoints.
    """
    return {"status": "success", "message": message, "data": data}


# PUBLIC_INTERFACE
@app.get("/", tags=["Health"], summary="Health Check")
def health_check():
    """
    Health check endpoint indicating the API is up.

    Returns:
        JSON with status and a simple message.
    """
    return _ocean_response({"service": "integration_backend", "health": "healthy"}, "service healthy")


# PUBLIC_INTERFACE
@app.get("/healthz", tags=["Health"], summary="Readiness probe", description="Simple readiness endpoint for container orchestration.")
def healthz():
    """
    Readiness endpoint. Returns OK status for probes/load balancers.
    """
    return {"status": "ok"}

# PUBLIC_INTERFACE
@app.get(
    "/health/redirect-uri",
    tags=["Health"],
    summary="Active Atlassian redirect URIs",
    description="Returns which redirect URIs are currently active for Jira and Confluence, for operator verification.",
)
def health_redirect_uri():
    """
    Return the effective redirect URIs used by the backend for Atlassian OAuth flows.
    """
    return _ocean_response(get_active_redirect_uris_debug(), "active redirect URIs")

# PUBLIC_INTERFACE
@app.get(
    "/health/authorize-url",
    tags=["Health"],
    summary="Verification: Jira authorize URL (no redirect, no state)",
    description="Returns the Atlassian authorize URL that would be used by /auth/jira/login with default scopes and no state. Use this to verify the exact redirect_uri parameter.",
)
def health_authorize_url_probe(request: Request):
    """
    Build and return the Atlassian authorize URL using the current Jira OAuth config without redirecting.
    This is intended for verification of the redirect_uri parameter.
    """
    cfg = get_jira_oauth_config()
    client_id = (cfg.get("client_id") or "").strip()
    # Use same guard/builder as login route
    try:
        # Strictly use JIRA_REDIRECT_URI; no fallbacks
        jira_override = os.getenv("JIRA_REDIRECT_URI", "").strip()
        redirect_uri = jira_override
    except Exception:
        redirect_uri = ""

    if not client_id or not redirect_uri:
        return _ocean_response(
            {
                "url": None,
                "error": "missing_config",
                "client_id_present": bool(client_id),
                "redirect_uri_present": bool(redirect_uri),
            },
            "oauth not configured",
        )
    default_scopes = "read:jira-work read:jira-user offline_access"
    url = build_atlassian_authorize_url(client_id=client_id, redirect_uri=redirect_uri, scopes=default_scopes, state=None)
    encoded_ri = urllib.parse.quote(redirect_uri, safe="")
    return _ocean_response({"url": url, "redirect_uri": redirect_uri, "redirect_uri_encoded": encoded_ri}, "authorize url")

# PUBLIC_INTERFACE
@app.get(
    "/health/redirect-pieces",
    tags=["Health"],
    summary="Verification: Computed Jira redirect pieces",
    description="Returns the scheme, host:port and path used to form the Jira redirect_uri, honoring X-Forwarded headers.",
)
def health_redirect_pieces(request: Request):
    """
    Compute the effective pieces used to build the Jira redirect_uri for this request.

    Returns:
        JSON including:
        - scheme
        - host_port (netloc)
        - path (always '/auth/jira/callback')
        - redirect_uri (full)
        - redirect_uri_encoded (urlencoded)
        - source: 'env' if JIRA_REDIRECT_URI is set, else 'request' or 'default'
    """
    try:
        override = os.getenv("JIRA_REDIRECT_URI", "").strip()
        redirect_uri = override
        source = "env"
        encoded = urllib.parse.quote(redirect_uri, safe="") if redirect_uri else ""
        parsed = urllib.parse.urlparse(redirect_uri) if redirect_uri else urllib.parse.urlparse("")
        return _ocean_response(
            {
                "scheme": parsed.scheme,
                "host_port": parsed.netloc,
                "path": parsed.path,
                "redirect_uri": redirect_uri,
                "redirect_uri_encoded": encoded,
                "source": source,
            },
            "computed redirect pieces",
        )
    except Exception as e:
        return _ocean_response({"error": str(e)}, "failed to compute pieces")


# Users (Public)

# -----------------------
# OAuth 2.0 for Atlassian - Jira
# -----------------------

# PUBLIC_INTERFACE
@app.options(
    "/auth/jira/login",
    tags=["Auth"],
    summary="CORS preflight for Jira login",
    description="Handles CORS preflight for Jira OAuth login endpoint."
)
def jira_login_options():
    """Respond OK to CORS preflight for /auth/jira/login."""
    # CORSMiddleware will inject the CORS headers. Returning empty 200 is sufficient.
    return JSONResponse(status_code=200, content={})

# PUBLIC_INTERFACE
@app.get(
    "/auth/jira/login",
    tags=["Auth"],
    summary="Start Jira OAuth 2.0 login",
    description=(
        "Returns JSON authorize URL by default; add ?redirect=true to receive a 307 redirect to Atlassian (Cache-Control: no-store). "
        "Response body contains the full authorize URL with audience=api.atlassian.com, response_type=code, prompt=consent, "
        "client_id from env, scope (default: 'read:jira-work read:jira-user offline_access'), and redirect_uri computed from env/request."
    ),
    response_model=OAuthAuthorizeURL,
)
def jira_login(
    request: Request,
    state: Optional[str] = None,
    scope: Optional[str] = None,
    redirect: Optional[bool] = False,
):
    """
    Initiate Jira OAuth 2.0 authorization flow using Atlassian OAuth 2.0 (3LO).

    Parameters:
        state: Optional client-provided opaque value. The backend will generate and sign its own CSRF state and
               embed the client value inside a JSON envelope.
        scope: Optional space-separated scopes. If not provided, defaults to commonly used scopes configured in your app.
        redirect: Optional boolean. If true, this endpoint issues a 307 Temporary Redirect to the Atlassian authorize URL
                  with 'Cache-Control: no-store'. If false/absent, returns JSON { "url": "<authorize_url>" }.

    Returns:
        - When redirect is true: 307 redirect to Atlassian authorize URL with Cache-Control: no-store
        - Otherwise: 200 JSON with {"url": "<authorize_url>"} (or 400 with config details if misconfigured)
    """
    provider = "jira"
    try:
        _log_event(
            logging.INFO,
            "oauth_login_start",
            request,
            provider=provider,
            has_state=bool(state),
            scope_count=(len(scope.split()) if scope else 0),
            redirect_flag=bool(redirect),
        )

        cfg = get_jira_oauth_config()
        client_id = (cfg.get("client_id") or "").strip()
        client_secret = (cfg.get("client_secret") or "").strip()
        # Build redirect_uri with strict priority: env var JIRA_REDIRECT_URI
        app_env = (cfg.get("app_env") or "production").lower()
        dev_mode = str(cfg.get("dev_mode") or "").lower() in ("true", "1", "yes")

        try:
            override = os.getenv("JIRA_REDIRECT_URI", "").strip()
            redirect_uri = override
            _log_event(
                logging.INFO,
                "oauth_redirect_uri_source",
                request,
                provider=provider,
                source_env="JIRA_REDIRECT_URI",
                redirect_uri=redirect_uri,
            )
        except Exception as e:
            _log_event(logging.WARNING, "oauth_redirect_uri_builder_exception", request, provider=provider, error=str(e))
            redirect_uri = ""

        # Presence flags
        presence = {
            "client_id_present": bool(client_id),
            "client_secret_present": bool(client_secret),
            "redirect_uri_present": bool(redirect_uri),
        }
        missing = {k.replace("_present", ""): not v for k, v in presence.items()}

        env_debug = get_jira_oauth_env_debug()

        if any(missing.values()):
            reasons = []
            if missing.get("client_id"):
                reasons.append("client_id not set or empty")
            if missing.get("client_secret"):
                reasons.append("client_secret not set or empty")
            if missing.get("redirect_uri"):
                reasons.append("redirect_uri not set or empty")

            if dev_mode or app_env == "development":
                mock_url = "https://auth.atlassian.com/authorize?mock=true"
                _log_event(
                    logging.WARNING,
                    "oauth_login_mock_dev",
                    request,
                    provider=provider,
                    mock_redirect=mock_url,
                    missing=missing,
                    env_debug=env_debug,
                    reasons=reasons,
                )
                return JSONResponse(
                    status_code=200,
                    content={
                        "url": mock_url,
                        "provider": provider,
                        "dev": True,
                        "missing": missing,
                        "details": {
                            "reasons": reasons,
                            "env_sources": {
                                "client_id": env_debug["client_id"]["source"],
                                "client_secret": env_debug["client_secret"]["source"],
                                "redirect_uri": env_debug["redirect_uri"]["source"],
                            },
                        },
                        "env_bootstrap": get_env_bootstrap_debug(),
                    },
                )

            _log_event(
                logging.ERROR,
                "oauth_login_config_error",
                request,
                provider=provider,
                missing=missing,
                env_debug=env_debug,
                reasons=reasons,
            )
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "message": "Jira OAuth is not fully configured. Provide JIRA_OAUTH_CLIENT_ID, JIRA_OAUTH_CLIENT_SECRET, and ATLASSIAN_OAUTH_REDIRECT_URI (exact value from Atlassian app).",
                    "missing": missing,
                    "details": {
                        "reasons": reasons,
                        "env_sources": {
                            "client_id": env_debug["client_id"]["source"],
                            "client_secret": env_debug["client_secret"]["source"],
                            "redirect_uri": env_debug["redirect_uri"]["source"],
                        },
                        "redirect_uri_analysis": env_debug["redirect_uri"].get("analysis", {}),
                    },
                    "env_bootstrap": get_env_bootstrap_debug(),
                },
            )

        # Default scopes (can be overridden via query param)
        default_scopes = [
            "read:jira-work",
            "read:jira-user",
            "offline_access",
        ]
        scopes = scope or " ".join(default_scopes)

        # Non-blocking analysis for observability
        redirect_analysis = env_debug["redirect_uri"].get("analysis", {})

        # Build CSRF state and set it as signed cookie; include in authorize URL.
        csrf_raw = _gen_csrf_state()
        signed_csrf = _sign_state(csrf_raw)
        state_cookie_value = signed_csrf

        compound_state_obj = {"csrf": signed_csrf}
        if state:
            compound_state_obj["client"] = state
        compound_state = json.dumps(compound_state_obj, separators=(",", ":"))

        url = build_atlassian_authorize_url(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=compound_state,
        )

        _log_event(
            logging.INFO,
            "oauth_final_redirect_uri_debug",
            request,
            provider=provider,
            final_redirect_uri=redirect_uri,
            authorize_url=url,
        )
        APP_LOGGER.info(
            "Jira OAuth using redirect URI",
            extra={
                "event": "oauth_redirect_uri_in_use",
                "provider": provider,
                "redirect_uri": redirect_uri,
            },
        )

        _log_event(
            logging.INFO,
            "oauth_login_redirect",
            request,
            provider=provider,
            authorize_endpoint="https://auth.atlassian.com/authorize",
            has_state=bool(state),
            scope_count=(len(scopes.split()) if scopes else 0),
            configured_redirect_uri_present=bool(redirect_uri),
            configured_redirect_uri=redirect_uri,
            redirect_uri_analysis=redirect_analysis,
            env_sources={
                "client_id": env_debug["client_id"]["source"],
                "client_secret": env_debug["client_secret"]["source"],
                "redirect_uri": env_debug["redirect_uri"]["source"],
            },
            chosen_mode=("http_redirect" if redirect else "json_url"),
        )

        if redirect:
            response = RedirectResponse(url=url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
            response.headers["Cache-Control"] = "no-store"
            response.set_cookie(
                key=_STATE_COOKIE_NAME,
                value=state_cookie_value,
                max_age=_STATE_COOKIE_TTL,
                httponly=True,
                secure=True,
                samesite="lax",
                path="/",
            )
            _log_event(logging.INFO, "oauth_state_cookie_set", request, provider=provider, cookie=_STATE_COOKIE_NAME, mode="redirect")
            return response

        # JSON flow: also set the cookie so the browser carries it to callback after navigation
        response = JSONResponse(status_code=200, content={"url": url})
        response.set_cookie(
            key=_STATE_COOKIE_NAME,
            value=state_cookie_value,
            max_age=_STATE_COOKIE_TTL,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )
        _log_event(logging.INFO, "oauth_state_cookie_set", request, provider=provider, cookie=_STATE_COOKIE_NAME, mode="json")
        return response
    except HTTPException:
        APP_LOGGER.exception("OAuth login HTTPException", extra={
            "request_id": getattr(request.state, "request_id", None),
            "event": "oauth_login_error",
            "provider": provider,
            "path": request.url.path,
        })
        raise
    except Exception:
        APP_LOGGER.exception("OAuth login error", extra={
            "request_id": getattr(request.state, "request_id", None),
            "event": "oauth_login_error",
            "provider": provider,
            "path": request.url.path,
        })
        raise


# PUBLIC_INTERFACE
@app.get(
    "/auth/jira/callback",
    tags=["Auth"],
    summary="Jira OAuth 2.0 callback",
    description=(
        "Handles Atlassian redirect, exchanges code for tokens, stores them on the first user (or targeted later), and redirects back to frontend.\n"
        "Notes: Requires 'state' generated by backend at /auth/jira/login. The 'state' must contain a backend-generated CSRF token and match the signed cookie; otherwise returns 422."
    ),
    name="jira_callback",
)
def _parse_state_map(state: Optional[str]) -> Dict[str, Any]:
    """Best-effort parse of the OAuth 'state' to extract user hints."""
    if not state:
        return {}
    # Already URL-decoded by FastAPI/Starlette
    s = state.strip()
    # Try JSON first
    try:
        j = json.loads(s)
        if isinstance(j, dict):
            return j
    except Exception:
        pass
    # Try querystring format: user_id=...&email=...
    try:
        qs = urllib.parse.parse_qs(s, keep_blank_values=False)
        flat = {k: (v[0] if isinstance(v, list) and v else v) for k, v in qs.items()}
        if any(k in flat for k in ("user_id", "uid", "email")):
            return flat
    except Exception:
        pass
    # Try simple prefixes like "uid:<id>" or "email:<addr>"
    try:
        if s.lower().startswith("uid:") or s.lower().startswith("user_id:"):
            return {"user_id": s.split(":", 1)[1]}
        if s.lower().startswith("email:"):
            return {"email": s.split(":", 1)[1]}
    except Exception:
        pass
    return {}


def _resolve_user_from_state(db, state: Optional[str]):
    """Attempt to resolve an existing or target user from the provided state."""
    hints = _parse_state_map(state)
    # user_id hint
    uid = hints.get("user_id") or hints.get("uid")
    if uid:
        try:
            uid_int = int(str(uid).strip())
            user = get_user_by_id(db, uid_int)
            if user:
                return user, {"method": "state_user_id", "user_id": uid_int}
        except Exception:
            pass
    # email hint
    email = hints.get("email")
    if email and isinstance(email, str) and "@" in email:
        email_norm = email.strip()
        # Find existing or create idempotently as a target
        existing = get_user_by_email(db, email_norm)
        if existing:
            return existing, {"method": "state_email_existing", "email": email_norm}
        user = create_user(db, email=email_norm, display_name=hints.get("display_name") or None)
        return user, {"method": "state_email_created", "email": email_norm}
    return None, {"method": "no_state_match"}


def _ensure_target_user(db, request: Request, state: Optional[str]):
    """Return a user to associate tokens with; create placeholder if none exists."""
    # 1) Try to resolve from state
    user, meta = _resolve_user_from_state(db, state)
    if user:
        _log_event(logging.INFO, "oauth_state_user_resolved", request, provider=None, resolved=meta)
        return user, meta

    # 2) Use first existing user if present
    users = list_users(db)
    if users:
        return users[0], {"method": "first_user"}

    # 3) Create placeholder user
    placeholder_email = f"oauth-user-{uuid.uuid4().hex}@example.local"
    user = create_user(db, email=placeholder_email, display_name="First Login")
    _log_event(logging.INFO, "oauth_placeholder_user_created", request, user_id=user.id, email=placeholder_email)
    return user, {"method": "placeholder_created", "email": placeholder_email}


async def jira_callback(
    request: Request,
    db=Depends(get_db),
    code: Optional[str] = None,
    state: Optional[str] = None,
):
    """
    Jira OAuth callback handler that delegates token exchange/persistence to the Jira connector,
    then redirects to the frontend success route.

    Redirect:
      APP_FRONTEND_URL + "/oauth/jira?status=success&tenant_id=<tid>&state=<state>&provider=jira"

    Notes:
      - Always return a 307 redirect with Cache-Control: no-store on success.
      - Requires a valid server-generated CSRF 'state' that matches the signed cookie set at /auth/jira/login.
    """
    provider = "jira"
    _log_event(logging.INFO, "oauth_callback_received", request, provider=provider, has_state=bool(state))

    # Strict CSRF/state validation
    cookie_state = request.cookies.get(_STATE_COOKIE_NAME)
    if not state:
        _log_event(logging.ERROR, "oauth_state_missing", request, provider=provider, status_code=422)
        # Clear any existing cookie defensively
        resp = JSONResponse(status_code=422, content={"detail": "Missing state parameter"})
        resp.delete_cookie(_STATE_COOKIE_NAME, path="/")
        return resp

    csrf_from_state: Optional[str] = None
    try:
        parsed = json.loads(state)
        if isinstance(parsed, dict):
            csrf_from_state = parsed.get("csrf") if isinstance(parsed.get("csrf"), str) else None
    except Exception:
        csrf_from_state = None

    if not csrf_from_state:
        _log_event(logging.ERROR, "oauth_state_invalid_format", request, provider=provider, status_code=422)
        resp = JSONResponse(status_code=422, content={"detail": "Invalid state format"})
        resp.delete_cookie(_STATE_COOKIE_NAME, path="/")
        return resp

    if not cookie_state:
        _log_event(logging.ERROR, "oauth_state_cookie_missing", request, provider=provider, status_code=422)
        resp = JSONResponse(status_code=422, content={"detail": "State cookie missing"})
        resp.delete_cookie(_STATE_COOKIE_NAME, path="/")
        return resp

    # Verify signature and constant-time match with cookie
    if not _verify_signed_state(csrf_from_state) or not hmac.compare_digest(str(cookie_state), str(csrf_from_state)):
        _log_event(logging.ERROR, "oauth_state_mismatch", request, provider=provider, status_code=422)
        resp = JSONResponse(status_code=422, content={"detail": "State mismatch"})
        resp.delete_cookie(_STATE_COOKIE_NAME, path="/")
        return resp

    # Resolve tenant id from state if present; else use default
    tenant_id = "default"
    if state:
        try:
            j = json.loads(state)
            if isinstance(j, dict) and j.get("tenant_id"):
                tenant_id = str(j.get("tenant_id"))
        except Exception:
            # fall back to querystring parsing
            try:
                qs = urllib.parse.parse_qs(state)
                if "tenant_id" in qs and qs.get("tenant_id"):
                    tenant_id = str(qs.get("tenant_id")[0])
            except Exception:
                pass
    try:
        if not code:
            _log_event(logging.ERROR, "oauth_missing_code", request, provider=provider, status_code=400)
            raise HTTPException(status_code=400, detail="Missing authorization code")

        # Delegate to Jira connector for token exchange/persistence (sync connector on sync thread)
        from src.connectors.jira.impl import JiraConnector
        connector = JiraConnector().with_db(db)
        connector.oauth_callback(code=code, tenant_id=tenant_id, state=state)

        # Build frontend redirect URL with required params
        frontend_base = get_frontend_base_url_default()
        return_path = "/oauth/jira"
        params = {
            "status": "success",
            "tenant_id": tenant_id,
            "state": state or "",
            "provider": "jira",
        }
        redirect_to = f"{frontend_base.rstrip('/')}{return_path}?{urllib.parse.urlencode(params)}" if frontend_base else f"/oauth/jira?{urllib.parse.urlencode(params)}"
        _log_event(logging.INFO, "frontend_redirect", request, provider=provider, redirect=redirect_to)
        response = RedirectResponse(url=redirect_to, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
        response.headers["Cache-Control"] = "no-store"
        # Rotate/clear state cookie after successful validation and redirect
        response.delete_cookie(_STATE_COOKIE_NAME, path="/")
        return response
    except HTTPException:
        APP_LOGGER.exception("OAuth callback HTTPException", extra={
            "request_id": getattr(request.state, "request_id", None),
            "event": "oauth_callback_error",
            "provider": provider,
            "path": request.url.path,
        })
        raise
    except Exception:
        APP_LOGGER.exception("OAuth callback error", extra={
            "request_id": getattr(request.state, "request_id", None),
            "event": "oauth_callback_error",
            "provider": provider,
            "path": request.url.path,
        })
        raise


# PUBLIC_INTERFACE
@app.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    tags=["Users"],
    summary="Create user",
    description="Create a new user or return an existing one if the email already exists (idempotent).",
)
def create_user_endpoint(payload: UserCreate, db=Depends(get_db)):
    """
    Create or idempotently fetch a user.

    Parameters:
        payload: UserCreate - includes optional placeholder tokens for JIRA and Confluence
    Returns:
        UserRead
    """
    user = create_user(
        db,
        email=payload.email,
        display_name=payload.display_name,
        jira_token=payload.jira_token,
        confluence_token=payload.confluence_token,
        jira_base_url=payload.jira_base_url,
        confluence_base_url=payload.confluence_base_url,
    )
    return user


# PUBLIC_INTERFACE
@app.get(
    "/users",
    response_model=List[UserRead],
    tags=["Users"],
    summary="List users",
    description="List all users.",
)
def list_users_endpoint(db=Depends(get_db)):
    """
    List all users.

    Note:
        This endpoint is public and does not require authentication.
    """
    return list_users(db)


# PUBLIC_INTERFACE
@app.get(
    "/users/{user_id}",
    response_model=UserRead,
    tags=["Users"],
    summary="Get user by ID",
    description="Retrieve a user by its internal ID.",
)
def get_user_endpoint(user_id: int, db=Depends(get_db)):
    """
    Get a single user by ID.

    Raises:
        404 if user not found.
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# -----------------------
# Integrations - Connect (Public demo flows)

# -----------------------
# OAuth 2.0 for Atlassian - Confluence
# -----------------------

# PUBLIC_INTERFACE
@app.get(
    "/auth/confluence/login",
    tags=["Auth"],
    summary="Start Confluence OAuth 2.0 login",
    description="Returns JSON authorize URL by default; add ?redirect=true to receive a 307 redirect to Atlassian (Cache-Control: no-store).",
)
def confluence_login(
    request: Request,
    state: Optional[str] = None,
    scope: Optional[str] = None,
    redirect: Optional[bool] = False,
):
    """
    Initiate Confluence OAuth 2.0 authorization flow with secure backend-generated state.

    Parameters:
        state: Optional client-provided value. Backend generates CSRF state and embeds client value as hint.
        scope: Optional scope string; defaults to sensible Confluence scopes.
        redirect: If true, 307 redirect to Atlassian; else return JSON { "url": "<authorize_url>" }.

    Behavior:
        - Generates cryptographically random CSRF state, signs it, stores as Secure HttpOnly cookie (SameSite=Lax, 10m TTL).
        - Includes compound state (with signed CSRF) in authorize URL.
        - redirect=false JSON flow sets cookie and returns the URL for frontend to navigate.
    """
    provider = "confluence"
    try:
        _log_event(
            logging.INFO,
            "oauth_login_start",
            request,
            provider=provider,
            has_state=bool(state),
            scope_count=(len(scope.split()) if scope else 0),
            redirect_flag=bool(redirect),
        )

        cfg = get_confluence_oauth_config()
        client_id = (cfg.get("client_id") or "").strip()
        redirect_uri = (cfg.get("redirect_uri") or "").strip()
        if not client_id or not redirect_uri:
            _log_event(logging.ERROR, "oauth_login_config_error", request, provider=provider,
                       missing={"client_id": not bool(client_id), "redirect_uri": not bool(redirect_uri)})
            return JSONResponse(
                status_code=400,
                content={
                    "status": "error",
                    "message": "Confluence OAuth is not fully configured. Provide CONFLUENCE_OAUTH_CLIENT_ID and CONFLUENCE_OAUTH_REDIRECT_URI (or Jira defaults).",
                    "missing": {"client_id": not bool(client_id), "redirect_uri": not bool(redirect_uri)},
                },
            )

        default_scopes = [
            "read:confluence-content.all",
            "read:confluence-space.summary",
            "offline_access",
        ]
        scopes = scope or " ".join(default_scopes)

        # CSRF state generation and cookie set
        csrf_raw = _gen_csrf_state()
        signed_csrf = _sign_state(csrf_raw)
        compound_state_obj = {"csrf": signed_csrf}
        if state:
            compound_state_obj["client"] = state
        compound_state = json.dumps(compound_state_obj, separators=(",", ":"))

        url = build_atlassian_authorize_url(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            state=compound_state,
        )

        _log_event(
            logging.INFO,
            "oauth_authorize_url_echo",
            request,
            provider=provider,
            authorize_url=url,
        )

        if redirect:
            response = RedirectResponse(url=url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
            response.headers["Cache-Control"] = "no-store"
            response.set_cookie(
                key=_STATE_COOKIE_NAME,
                value=signed_csrf,
                max_age=_STATE_COOKIE_TTL,
                httponly=True,
                secure=True,
                samesite="lax",
                path="/",
            )
            _log_event(logging.INFO, "oauth_state_cookie_set", request, provider=provider, cookie=_STATE_COOKIE_NAME, mode="redirect")
            return response

        response = JSONResponse(status_code=200, content={"url": url})
        response.set_cookie(
            key=_STATE_COOKIE_NAME,
            value=signed_csrf,
            max_age=_STATE_COOKIE_TTL,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )
        _log_event(logging.INFO, "oauth_state_cookie_set", request, provider=provider, cookie=_STATE_COOKIE_NAME, mode="json")
        return response
    except HTTPException:
        APP_LOGGER.exception("OAuth login HTTPException", extra={
            "request_id": getattr(request.state, "request_id", None),
            "event": "oauth_login_error",
            "provider": provider,
            "path": request.url.path,
        })
        raise
    except Exception:
        APP_LOGGER.exception("OAuth login error", extra={
            "request_id": getattr(request.state, "request_id", None),
            "event": "oauth_login_error",
            "provider": provider,
            "path": request.url.path,
        })
        raise


# PUBLIC_INTERFACE
@app.get(
    "/auth/confluence/callback",
    tags=["Auth"],
    summary="Confluence OAuth 2.0 callback",
    description="Handles Atlassian redirect, exchanges code for tokens, stores them on the first user, and redirects back to frontend. Requires backend-generated 'state'.",
)
async def confluence_callback(request: Request, db=Depends(get_db), code: Optional[str] = None, state: Optional[str] = None):
    """
    Complete Confluence OAuth 2.0 flow (token exchange and persistence) with strict CSRF state validation.

    Notes:
      - Requires server-generated 'state' containing signed CSRF; must match HttpOnly cookie set at /auth/confluence/login.
      - On success, returns 307 redirect to frontend with Cache-Control: no-store and clears state cookie.
    """
    provider = "confluence"
    _log_event(logging.INFO, "oauth_callback_received", request, provider=provider, has_state=bool(state))
    try:
        if not state:
            _log_event(logging.ERROR, "oauth_state_missing", request, provider=provider, status_code=422)
            resp = JSONResponse(status_code=422, content={"detail": "Missing state parameter"})
            resp.delete_cookie(_STATE_COOKIE_NAME, path="/")
            return resp

        # Extract CSRF from state JSON
        csrf_from_state: Optional[str] = None
        try:
            parsed = json.loads(state)
            if isinstance(parsed, dict):
                csrf_from_state = parsed.get("csrf") if isinstance(parsed.get("csrf"), str) else None
        except Exception:
            csrf_from_state = None

        if not csrf_from_state:
            _log_event(logging.ERROR, "oauth_state_invalid_format", request, provider=provider, status_code=422)
            resp = JSONResponse(status_code=422, content={"detail": "Invalid state format"})
            resp.delete_cookie(_STATE_COOKIE_NAME, path="/")
            return resp

        cookie_state = request.cookies.get(_STATE_COOKIE_NAME)
        if not cookie_state:
            _log_event(logging.ERROR, "oauth_state_cookie_missing", request, provider=provider, status_code=422)
            resp = JSONResponse(status_code=422, content={"detail": "State cookie missing"})
            resp.delete_cookie(_STATE_COOKIE_NAME, path="/")
            return resp

        if not _verify_signed_state(csrf_from_state) or not hmac.compare_digest(str(cookie_state), str(csrf_from_state)):
            _log_event(logging.ERROR, "oauth_state_mismatch", request, provider=provider, status_code=422)
            resp = JSONResponse(status_code=422, content={"detail": "State mismatch"})
            resp.delete_cookie(_STATE_COOKIE_NAME, path="/")
            return resp

        if not code:
            _log_event(logging.ERROR, "oauth_missing_code", request, provider=provider, status_code=400)
            raise HTTPException(status_code=400, detail="Missing authorization code")

        cfg = get_confluence_oauth_config()
        client_id = (cfg.get("client_id") or "").strip()
        client_secret = (cfg.get("client_secret") or "").strip()
        redirect_uri = (cfg.get("redirect_uri") or "").strip()
        if not client_id or not client_secret or not redirect_uri:
            _log_event(logging.ERROR, "oauth_callback_config_error", request, provider=provider, status_code=400)
            raise HTTPException(
                status_code=400,
                detail="Confluence OAuth is not configured. Missing client_id/client_secret/redirect_uri.",
            )

        token_url = "https://auth.atlassian.com/oauth/token"
        data = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }

        _log_event(logging.INFO, "token_exchange_start", request, provider=provider)
        async with httpx.AsyncClient(timeout=20.0) as client:
            try:
                token_resp = await client.post(token_url, json=data, headers={"Content-Type": "application/json"})
            except httpx.RequestError as rex:
                APP_LOGGER.exception("Token exchange request error", extra={
                    "request_id": getattr(request.state, "request_id", None),
                    "event": "token_exchange_error",
                    "provider": provider,
                    "path": request.url.path,
                })
                raise HTTPException(status_code=502, detail="Token exchange request failed") from rex

        _log_event(
            logging.INFO,
            "token_exchange_response",
            request,
            provider=provider,
            status_code=token_resp.status_code,
        )

        if token_resp.status_code != 200:
            APP_LOGGER.error(
                "Token exchange failed",
                extra={
                    "request_id": getattr(request.state, "request_id", None),
                    "event": "token_exchange_failed",
                    "provider": provider,
                    "path": request.url.path,
                    "status_code": token_resp.status_code,
                },
            )
            raise HTTPException(status_code=502, detail="Token exchange failed")

        token_json = token_resp.json()

        access_token = token_json.get("access_token")
        refresh_token = token_json.get("refresh_token")
        expires_in = token_json.get("expires_in")
        _log_event(
            logging.INFO,
            "token_exchange_success",
            request,
            provider=provider,
            access_token_present=bool(access_token),
            refresh_token_present=bool(refresh_token),
            expires_in=expires_in,
        )

        if not access_token:
            _log_event(logging.ERROR, "oauth_no_access_token", request, provider=provider, status_code=502)
            raise HTTPException(status_code=502, detail="No access token returned by Atlassian")

        # Resolve or create a user to associate with this connection
        user, user_meta = _ensure_target_user(db, request, state)

        user.confluence_token = access_token
        user.confluence_refresh_token = refresh_token
        user.confluence_expires_at = int(time.time()) + int(expires_in or 0)
        from src.api.oauth_config import get_atlassian_base_url

        base = get_atlassian_base_url()
        user.confluence_base_url = (base.rstrip("/") + "/wiki") if base else user.confluence_base_url
        db.commit()
        db.refresh(user)

        _log_event(logging.INFO, "oauth_user_token_persisted", request, provider=provider, user_id=user.id)

        frontend = get_frontend_base_url_default() or "/"
        params = {
            "provider": provider,
            "status": "success",
            "state": state or "",
            "user_id": str(user.id),
        }
        redirect_to = f"{frontend.rstrip('/')}/oauth/callback?{urllib.parse.urlencode(params)}"
        _log_event(logging.INFO, "frontend_redirect", request, provider=provider, redirect=redirect_to)
        response = RedirectResponse(redirect_to, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
        response.headers["Cache-Control"] = "no-store"
        response.delete_cookie(_STATE_COOKIE_NAME, path="/")
        return response
    except HTTPException:
        APP_LOGGER.exception("OAuth callback HTTPException", extra={
            "request_id": getattr(request.state, "request_id", None),
            "event": "oauth_callback_error",
            "provider": provider,
            "path": request.url.path,
        })
        raise
    except Exception:
        APP_LOGGER.exception("OAuth callback error", extra={
            "request_id": getattr(request.state, "request_id", None),
            "event": "oauth_callback_error",
            "provider": provider,
            "path": request.url.path,
        })
        raise


# -----------------------

# PUBLIC_INTERFACE
@app.post(
    "/integrations/jira/connect",
    tags=["Integrations"],
    response_model=ConnectResponse,
    summary="Connect JIRA (auto, no user input)",
    description="Use OAuth 2.0 flow for JIRA. This endpoint now returns guidance to start /auth/jira/login.",
)
def connect_jira(db=Depends(get_db), payload: UserCreate | None = None):
    """
    Store JIRA connection details using hard-coded credentials (demo-only).
    If a user exists for the provided email, it will be used; otherwise a user can be created first via /users.

    Returns:
        ConnectResponse summary of saved settings including optional redirect_url.
    """
    # This demo endpoint no longer persists tokens directly. It guides the client to start OAuth.
    from src.api.oauth_config import get_atlassian_base_url
    base_url = get_atlassian_base_url()
    if not base_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Atlassian base URL is not configured")

    # For demo simplicity, if payload with email is provided, upsert/get that user; else use first user if any.
    target_user = None
    if payload and payload.email:
        target_user = create_user(
            db,
            email=payload.email,
            display_name=payload.display_name,
            jira_token=payload.jira_token,
            confluence_token=payload.confluence_token,
            jira_base_url=payload.jira_base_url,
            confluence_base_url=payload.confluence_base_url,
        )
    else:
        users = list_users(db)
        target_user = users[0] if users else None

    if not target_user:
        raise HTTPException(
            status_code=400,
            detail="No user available. Create a user first via POST /users (provide an email).",
        )

    # Keep/update user's base_url only; do not set token here.
    target_user.jira_base_url = base_url
    db.commit()
    db.refresh(target_user)

    redirect = "/auth/jira/login"  # frontend should navigate here to start OAuth
    return ConnectResponse(provider="jira", base_url=target_user.jira_base_url or "", connected=True, redirect_url=redirect)


# PUBLIC_INTERFACE
@app.post(
    "/integrations/confluence/connect",
    tags=["Integrations"],
    response_model=ConnectResponse,
    summary="Connect Confluence (auto, no user input)",
    description="Use OAuth 2.0 flow for Confluence. This endpoint now returns guidance to start /auth/confluence/login.",
)
def connect_confluence(db=Depends(get_db), payload: UserCreate | None = None):
    """
    Store Confluence connection details using hard-coded credentials (demo-only).
    If a user exists for the provided email, it will be used; otherwise a user can be created first via /users.

    Returns:
        ConnectResponse summary of saved settings including optional redirect_url.
    """
    from src.api.oauth_config import get_atlassian_base_url
    base_core = get_atlassian_base_url()
    base_url = (base_core.rstrip("/") + "/wiki") if base_core else None

    if not base_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Atlassian base URL is not configured")

    target_user = None
    if payload and payload.email:
        target_user = create_user(
            db,
            email=payload.email,
            display_name=payload.display_name,
            jira_token=payload.jira_token,
            confluence_token=payload.confluence_token,
            jira_base_url=payload.jira_base_url,
            confluence_base_url=payload.confluence_base_url,
        )
    else:
        users = list_users(db)
        target_user = users[0] if users else None

    if not target_user:
        raise HTTPException(
            status_code=400,
            detail="No user available. Create a user first via POST /users (provide an email).",
        )

    target_user.confluence_base_url = base_url
    db.commit()
    db.refresh(target_user)

    redirect = "/auth/confluence/login"
    return ConnectResponse(provider="confluence", base_url=target_user.confluence_base_url or "", connected=True, redirect_url=redirect)


# -----------------------
# Integrations - Fetch (placeholders) - Public
# -----------------------

# PUBLIC_INTERFACE
@app.get(
    "/integrations/jira/projects/fetch",
    tags=["Integrations", "JIRA Projects"],
    response_model=JiraProjectsFetchResponse,
    summary="Fetch JIRA projects (placeholder)",
    description="Fetches projects from JIRA for a user (demo: returns stored projects only). If none specified, uses the first user.",
)
def fetch_jira_projects(db=Depends(get_db), owner_id: int | None = None):
    """
    Placeholder fetch: uses stored base URL and token to query JIRA (omitted), and returns what's stored.
    If owner_id is not provided, the first user (if any) is used.
    """
    resolved_owner_id = owner_id
    if resolved_owner_id is None:
        users = list_users(db)
        if not users:
            return JiraProjectsFetchResponse(provider="jira", items=[])
        resolved_owner_id = users[0].id
    projects = list_jira_projects_for_user(db, resolved_owner_id)
    return JiraProjectsFetchResponse(provider="jira", items=projects)


# PUBLIC_INTERFACE
@app.get(
    "/integrations/confluence/pages/fetch",
    tags=["Integrations", "Confluence Pages"],
    response_model=ConfluencePagesFetchResponse,
    summary="Fetch Confluence pages (placeholder)",
    description="Fetches pages from Confluence for a user (demo: returns stored pages only). If none specified, uses the first user.",
)
def fetch_confluence_pages(db=Depends(get_db), owner_id: int | None = None):
    """
    Placeholder fetch: uses stored base URL and token to query Confluence (omitted), and returns what's stored.
    If owner_id is not provided, the first user (if any) is used.
    """
    resolved_owner_id = owner_id
    if resolved_owner_id is None:
        users = list_users(db)
        if not users:
            return ConfluencePagesFetchResponse(provider="confluence", items=[])
        resolved_owner_id = users[0].id
    pages = list_confluence_pages_for_user(db, resolved_owner_id)
    return ConfluencePagesFetchResponse(provider="confluence", items=pages)


# JIRA Projects (Public)
# PUBLIC_INTERFACE
@app.post(
    "/jira/projects",
    response_model=JiraProjectRead,
    status_code=status.HTTP_201_CREATED,
    tags=["JIRA Projects"],
    summary="Upsert JIRA project",
    description="Create or update a JIRA project for a given user keyed by (owner_id, key).",
)
def upsert_jira_project_endpoint(payload: JiraProjectCreate, db=Depends(get_db)):
    """
    Upsert a JIRA project tied to a user.
    """
    return upsert_jira_project(
        db,
        owner_id=payload.owner_id,
        key=payload.key,
        name=payload.name,
        lead=payload.lead,
        url=payload.url,
    )


# PUBLIC_INTERFACE
@app.get(
    "/jira/projects/{owner_id}",
    response_model=List[JiraProjectRead],
    tags=["JIRA Projects"],
    summary="List JIRA projects for user",
    description="List all JIRA projects owned by the given user.",
)
def list_jira_projects_endpoint(owner_id: int, db=Depends(get_db)):
    """
    List all stored JIRA projects for a specific owner.
    """
    return list_jira_projects_for_user(db, owner_id)


# Confluence Pages (Public)
# PUBLIC_INTERFACE
@app.post(
    "/confluence/pages",
    response_model=ConfluencePageRead,
    status_code=status.HTTP_201_CREATED,
    tags=["Confluence Pages"],
    summary="Upsert Confluence page",
    description="Create or update a Confluence page for a given user keyed by (owner_id, space_key, page_id).",
)
def upsert_confluence_page_endpoint(payload: ConfluencePageCreate, db=Depends(get_db)):
    """
    Upsert a Confluence page tied to a user.
    """
    return upsert_confluence_page(
        db,
        owner_id=payload.owner_id,
        space_key=payload.space_key,
        page_id=payload.page_id,
        title=payload.title,
        url=payload.url,
    )


# PUBLIC_INTERFACE
@app.get(
    "/confluence/pages/{owner_id}",
    response_model=List[ConfluencePageRead],
    tags=["Confluence Pages"],
    summary="List Confluence pages for user",
    description="List all Confluence pages owned by the given user.",
)
def list_confluence_pages_endpoint(owner_id: int, db=Depends(get_db)):
    """
    List all stored Confluence pages for a specific owner.
    """
    return list_confluence_pages_for_user(db, owner_id)


# -----------------------
# Compatibility alias routes for proxies that do not strip `/api` prefix
# -----------------------

# PUBLIC_INTERFACE
@app.get(
    "/api/auth/jira/login",
    tags=["Auth"],
    summary="Alias: Start Jira OAuth 2.0 login (/api prefix)",
    description="Compatibility alias for environments where a proxy forwards '/api/auth/jira/login' to backend unchanged.",
)
def jira_login_api_alias(
    request: Request,
    state: Optional[str] = None,
    scope: Optional[str] = None,
    redirect: Optional[bool] = False,
):
    """
    Alias wrapper for /auth/jira/login to support '/api' prefixed routes through proxies.
    """
    _log_event(logging.INFO, "oauth_alias_route_invoked", request, provider="jira", alias="/api/auth/jira/login")
    return jira_login(request, state=state, scope=scope, redirect=redirect)


# PUBLIC_INTERFACE
@app.get(
    "/api/auth/jira/callback",
    tags=["Auth"],
    summary="Alias: Jira OAuth 2.0 callback (/api prefix)",
    description="Compatibility alias mapping '/api/auth/jira/callback' to the existing Jira callback handler.",
)
async def jira_callback_api_alias(request: Request, db=Depends(get_db), code: Optional[str] = None, state: Optional[str] = None):
    """
    Alias wrapper for /auth/jira/callback to support '/api' prefixed routes.
    Delegates to jira_callback which performs the redirect to frontend.
    """
    _log_event(logging.INFO, "oauth_alias_route_invoked", request, provider="jira", alias="/api/auth/jira/callback")
    return await jira_callback(request, db, code, state)


# PUBLIC_INTERFACE
@app.get(
    "/api/auth/confluence/login",
    tags=["Auth"],
    summary="Alias: Start Confluence OAuth 2.0 login (/api prefix)",
    description="Compatibility alias for environments where a proxy forwards '/api/auth/confluence/login' to backend unchanged.",
)
def confluence_login_api_alias(request: Request, state: Optional[str] = None, scope: Optional[str] = None):
    """
    Alias wrapper for /auth/confluence/login to support '/api' prefixed routes through proxies.
    """
    _log_event(logging.INFO, "oauth_alias_route_invoked", request, provider="confluence", alias="/api/auth/confluence/login")
    return confluence_login(request, state=state, scope=scope)


# PUBLIC_INTERFACE
@app.get(
    "/api/auth/confluence/callback",
    tags=["Auth"],
    summary="Alias: Confluence OAuth 2.0 callback (/api prefix)",
    description="Compatibility alias mapping '/api/auth/confluence/callback' to the existing Confluence callback handler.",
)
async def confluence_callback_api_alias(request: Request, db=Depends(get_db), code: Optional[str] = None, state: Optional[str] = None):
    """
    Alias wrapper for /auth/confluence/callback to support '/api' prefixed routes.
    """
    _log_event(logging.INFO, "oauth_alias_route_invoked", request, provider="confluence", alias="/api/auth/confluence/callback")
    return await confluence_callback(request, db, code, state)


# PUBLIC_INTERFACE
@app.get(
    "/api/oauth/atlassian/callback",
    tags=["Auth"],
    summary="Alias: Atlassian OAuth callback (/api)",
    description=(
        "Compatibility alias for Atlassian callback. By default routes to Jira handler. "
        "Ensure your Atlassian app Redirect URI matches this path or use '/api/auth/{jira|confluence}/callback'."
    ),
)
async def atlassian_callback_alias(request: Request, db=Depends(get_db), code: Optional[str] = None, state: Optional[str] = None):
    """
    Generic Atlassian callback alias that delegates to the Jira callback handler and then redirects to frontend.
    If you are using a dedicated Confluence app/client with a distinct redirect URI,
    prefer '/api/auth/confluence/callback' to avoid mismatched redirect_uri during token exchange.
    """
    _log_event(logging.INFO, "oauth_alias_route_invoked", request, provider="jira", alias="/api/oauth/atlassian/callback")
    return await jira_callback(request, db, code, state)
