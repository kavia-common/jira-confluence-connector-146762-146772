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
)

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

# CORS: prefer configured origins; fallback to "*"
from src.api.oauth_config import _SETTINGS as _SETTINGS_INTERNAL  # safe import inside backend
cors_origins_raw = _SETTINGS_INTERNAL.backend_cors_origins or "*"
origins = [o.strip() for o in cors_origins_raw.split(",")] if cors_origins_raw else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database tables (for demo; in production, prefer migrations)
Base.metadata.create_all(bind=engine)


def _ocean_response(data: Any, message: str = "ok") -> Dict[str, Any]:
    """
    Wrap responses using a simple 'Ocean Professional' style envelope.

    This keeps API responses consistent across endpoints.
    """
    return {"status": "success", "message": message, "data": data}


# Global unhandled exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Capture any unhandled exception, log it, and return a sanitized 500 with request_id."""
    rid = getattr(request.state, "request_id", None)
    _log_event(logging.ERROR, "unhandled_exception", request, status_code=500, error=str(exc))
    APP_LOGGER.exception("Unhandled exception", extra={
        "request_id": rid,
        "path": request.url.path,
        "method": request.method,
        "event": "unhandled_exception",
    })
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Internal Server Error", "request_id": rid},
    )


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


# Users (Public)

# -----------------------
# OAuth 2.0 for Atlassian - Jira
# -----------------------

# PUBLIC_INTERFACE
@app.get(
    "/auth/jira/login",
    tags=["Auth"],
    summary="Start Jira OAuth 2.0 login",
    description="Redirects the user to Atlassian authorization page. Frontend should open this URL to start the flow.",
)
def jira_login(request: Request, state: Optional[str] = None, scope: Optional[str] = None):
    """
    Initiate Jira OAuth 2.0 authorization flow using Atlassian OAuth 2.0 (3LO).
    Parameters:
        state: Optional opaque state to be returned by Atlassian to mitigate CSRF (frontend should generate and verify).
        scope: Optional space-separated scopes. If not provided, defaults to commonly used scopes configured in your app.
    Returns:
        200 JSON with {"url": "<authorize_url>"} for programmatic use, or 400 with details if misconfigured.
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
        )

        cfg = get_jira_oauth_config()
        client_id = (cfg.get("client_id") or "").strip()
        client_secret = (cfg.get("client_secret") or "").strip()
        redirect_uri = (cfg.get("redirect_uri") or "").strip()
        app_env = (cfg.get("app_env") or "production").lower()
        dev_mode = str(cfg.get("dev_mode") or "").lower() in ("true", "1", "yes")

        # Presence flags and derived missing map (True means the field is missing)
        presence = {
            "client_id_present": bool(client_id),
            "client_secret_present": bool(client_secret),
            "redirect_uri_present": bool(redirect_uri),
        }
        missing = {k.replace("_present", ""): not v for k, v in presence.items()}

        # Prepare masked, source-aware debug details (do not log raw values)
        env_debug = get_jira_oauth_env_debug()

        if any(missing.values()):
            reasons = []
            if missing.get("client_id"):
                reasons.append("client_id not set or empty")
            if missing.get("client_secret"):
                reasons.append("client_secret not set or empty")
            if missing.get("redirect_uri"):
                reasons.append("redirect_uri not set or empty")

            # In dev, return a mock URL to keep UX flowing while surfacing misconfig
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
                    "message": "Jira OAuth is not fully configured. Provide JIRA_OAUTH_CLIENT_ID, JIRA_OAUTH_CLIENT_SECRET, and JIRA_OAUTH_REDIRECT_URI (exact value from Atlassian app).",
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

        # Build authorize URL using EXACT redirect_uri from env (no normalization)
        url = build_atlassian_authorize_url(client_id=client_id, redirect_uri=redirect_uri, scopes=scopes, state=state)
        _log_event(
            logging.INFO,
            "oauth_login_redirect",
            request,
            provider=provider,
            authorize_endpoint="https://auth.atlassian.com/authorize",
            has_state=bool(state),
            scope_count=(len(scopes.split()) if scopes else 0),
            configured_redirect_uri_present=bool(redirect_uri),
            redirect_uri_analysis=redirect_analysis,
            env_sources={
                "client_id": env_debug["client_id"]["source"],
                "client_secret": env_debug["client_secret"]["source"],
                "redirect_uri": env_debug["redirect_uri"]["source"],
            },
        )
        # Return 200 with the URL for clients to navigate
        return JSONResponse(status_code=200, content={"url": url})
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
    description="Handles Atlassian redirect, exchanges code for tokens, stores them on the first user (or targeted later), and redirects back to frontend.",
)
async def jira_callback(request: Request, db=Depends(get_db), code: Optional[str] = None, state: Optional[str] = None):
    """
    Complete Jira OAuth 2.0 flow:
    - Exchange authorization code for access and refresh tokens
    - Store tokens and expiry on a user (demo: first user)
    - Redirect to frontend with status
    """
    provider = "jira"
    _log_event(logging.INFO, "oauth_callback_received", request, provider=provider)
    try:
        if not code:
            _log_event(logging.ERROR, "oauth_missing_code", request, provider=provider, status_code=400)
            raise HTTPException(status_code=400, detail="Missing authorization code")

        cfg = get_jira_oauth_config()
        client_id = cfg.get("client_id")
        client_secret = cfg.get("client_secret")
        redirect_uri = cfg.get("redirect_uri")
        if not client_id or not client_secret or not redirect_uri:
            # Distinguish config error as 400, not 500
            _log_event(logging.ERROR, "oauth_callback_config_error", request, provider=provider, status_code=400)
            raise HTTPException(
                status_code=400,
                detail="Jira OAuth is not configured. Missing client_id/client_secret/redirect_uri.",
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
            # Log failure without secrets
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
        expires_in = token_json.get("expires_in")  # seconds
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

        # For demo simplicity: store on the first user (or require selecting target later)
        users = list_users(db)
        if not users:
            _log_event(logging.ERROR, "oauth_no_user_available", request, provider=provider, status_code=400)
            raise HTTPException(status_code=400, detail="No user found. Create a user first via POST /users.")
        user = users[0]

        user.jira_token = access_token
        user.jira_refresh_token = refresh_token
        user.jira_expires_at = int(time.time()) + int(expires_in or 0)
        # store base URL if known from env
        from src.api.oauth_config import get_atlassian_base_url

        user.jira_base_url = get_atlassian_base_url() or user.jira_base_url
        db.commit()
        db.refresh(user)

        _log_event(logging.INFO, "oauth_user_token_persisted", request, provider=provider, user_id=user.id)

        # Redirect back to frontend (UI return URL)
        # Default route if FRONTEND not provided: https://vscode-internal-13311-beta.beta01.cloud.kavia.ai:3000/oauth/jira
        frontend_base = get_frontend_base_url_default()
        if not frontend_base:
            # Use the required default from task
            frontend_base = "https://vscode-internal-13311-beta.beta01.cloud.kavia.ai:3000"
        # Preferred callback route for the UI
        return_path = "/oauth/jira"
        # Preserve state and minimal info; do not leak tokens
        params = {
            "status": "success",
            "state": state or "",
            "user_id": str(user.id),
        }
        redirect_to = f"{frontend_base.rstrip('/')}{return_path}?{urllib.parse.urlencode(params)}"
        _log_event(logging.INFO, "frontend_redirect", request, provider=provider, redirect=redirect_to)
        return RedirectResponse(redirect_to)
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
    description="Redirects the user to Atlassian authorization page for Confluence scopes.",
)
def confluence_login(request: Request, state: Optional[str] = None, scope: Optional[str] = None):
    """
    Initiate Confluence OAuth 2.0 authorization flow.
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
        )

        cfg = get_confluence_oauth_config()
        client_id = cfg.get("client_id")
        redirect_uri = cfg.get("redirect_uri")
        if not client_id or not redirect_uri:
            _log_event(logging.ERROR, "oauth_login_config_error", request, provider=provider)
            raise HTTPException(status_code=500, detail="Confluence OAuth is not configured. Set environment variables.")

        default_scopes = [
            "read:confluence-content.all",
            "read:confluence-space.summary",
            "offline_access",
        ]
        scopes = scope or " ".join(default_scopes)

        authorize_url = "https://auth.atlassian.com/authorize"
        params = {
            "audience": "api.atlassian.com",
            "client_id": client_id,
            "scope": scopes,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "prompt": "consent",
        }
        if state:
            params["state"] = state
        url = f"{authorize_url}?{urllib.parse.urlencode(params)}"
        _log_event(
            logging.INFO,
            "oauth_login_redirect",
            request,
            provider=provider,
            authorize_endpoint=authorize_url,
            has_state=bool(state),
            scope_count=(len(scopes.split()) if scopes else 0),
        )
        return RedirectResponse(url)
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
    description="Handles Atlassian redirect, exchanges code for tokens, stores them on the first user, and redirects back to frontend.",
)
async def confluence_callback(request: Request, db=Depends(get_db), code: Optional[str] = None, state: Optional[str] = None):
    """
    Complete Confluence OAuth 2.0 flow (token exchange and persistence).
    """
    provider = "confluence"
    _log_event(logging.INFO, "oauth_callback_received", request, provider=provider)
    try:
        if not code:
            _log_event(logging.ERROR, "oauth_missing_code", request, provider=provider, status_code=400)
            raise HTTPException(status_code=400, detail="Missing authorization code")

        cfg = get_confluence_oauth_config()
        client_id = cfg.get("client_id")
        client_secret = cfg.get("client_secret")
        redirect_uri = cfg.get("redirect_uri")
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

        users = list_users(db)
        if not users:
            _log_event(logging.ERROR, "oauth_no_user_available", request, provider=provider, status_code=400)
            raise HTTPException(status_code=400, detail="No user found. Create a user first via POST /users.")
        user = users[0]

        user.confluence_token = access_token
        user.confluence_refresh_token = refresh_token
        user.confluence_expires_at = int(time.time()) + int(expires_in or 0)
        from src.api.oauth_config import get_atlassian_base_url

        # Commonly the wiki lives under <base>/wiki
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
        return RedirectResponse(redirect_to)
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
    # Lazy import to avoid circulars and keep dependency surface small
    # Removed legacy import of hardcoded credentials; OAuth flow is used instead.

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
    # Removed legacy import of hardcoded credentials; OAuth flow is used instead.

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
def jira_login_api_alias(request: Request, state: Optional[str] = None, scope: Optional[str] = None):
    """
    Alias wrapper for /auth/jira/login to support '/api' prefixed routes through proxies.
    """
    _log_event(logging.INFO, "oauth_alias_route_invoked", request, provider="jira", alias="/api/auth/jira/login")
    return jira_login(request, state=state, scope=scope)


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
    Generic Atlassian callback alias that delegates to the Jira callback handler.
    If you are using a dedicated Confluence app/client with a distinct redirect URI,
    prefer '/api/auth/confluence/callback' to avoid mismatched redirect_uri during token exchange.
    """
    _log_event(logging.INFO, "oauth_alias_route_invoked", request, provider="jira", alias="/api/oauth/atlassian/callback")
    return await jira_callback(request, db, code, state)
