import logging
import os
import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any
import urllib.parse
import base64

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles

from src.db.config import Base, engine

# optional dotenv
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv(override=False)
except Exception:
    pass

from src.api.oauth_config import (
    get_jira_oauth_config,
    build_atlassian_authorize_url,
    get_active_redirect_uris_debug,
)

# Logging
class SafeJSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.now(timezone.utc).isoformat()
        payload: Dict[str, Any] = {
            "timestamp": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "event": getattr(record, "event", None),
            "request_id": getattr(record, "request_id", None),
            "path": getattr(record, "path", None),
            "method": getattr(record, "method", None),
            "status_code": getattr(record, "status_code", None),
        }
        try:
            return json.dumps({k: v for k, v in payload.items() if v is not None}, ensure_ascii=False)
        except Exception:
            return f"{ts} {record.levelname} {record.name} {record.getMessage()}"


def _configure_logging() -> logging.Logger:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logger = logging.getLogger("integration_backend")
    logger.setLevel(level)
    if not logger.handlers:
        h = logging.StreamHandler()
        h.setLevel(level)
        h.setFormatter(SafeJSONFormatter())
        logger.addHandler(h)
        logger.propagate = False
    return logger


APP_LOGGER = _configure_logging()

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

# Middleware for Request ID
class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        request.state.request_id = request_id
        try:
            response = await call_next(request)
        except Exception:
            APP_LOGGER.exception("Unhandled exception", extra={"request_id": request_id, "path": request.url.path})
            raise
        response.headers["X-Request-ID"] = request_id
        return response

app.add_middleware(RequestIDMiddleware)

# CORS
configured = os.getenv("NEXT_PUBLIC_BACKEND_CORS_ORIGINS") or os.getenv("BACKEND_CORS_ORIGINS") or ""
configured_list = [o.strip() for o in configured.split(",")] if configured else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=configured_list,
    allow_credentials=True,
    allow_methods=["GET", "OPTIONS", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)

# DB init
Base.metadata.create_all(bind=engine)

# Mount connectors router
from src.api.routers import connectors as connectors_router  # noqa: E402
app.include_router(connectors_router.router)

# Mount Jira OAuth auth router
from src.api.jira_oauth import router as jira_oauth_router  # noqa: E402
app.include_router(jira_oauth_router)

# Mount static and serve favicon
static_dir = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "static"))
try:
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
except Exception:
    pass

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    fav_path = os.path.join(static_dir, "favicon.ico")
    if os.path.isfile(fav_path):
        return FileResponse(fav_path, media_type="image/x-icon")
    # 1x1 png fallback to avoid 404 noise
    png_base64 = (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR4nGNgYAAAAAMA"
        "ASsJTYQAAAAASUVORK5CYII="
    )
    data = base64.b64decode(png_base64)
    return Response(content=data, media_type="image/png")

# Health
def _ocean_response(data: Any, message: str = "ok") -> Dict[str, Any]:
    return {"status": "success", "message": message, "data": data}

@app.get("/", tags=["Health"], summary="Health Check")
def health_check():
    """Health check endpoint indicating the API is up."""
    return _ocean_response({"service": "integration_backend", "health": "healthy"}, "service healthy")

@app.get("/healthz", tags=["Health"], summary="Readiness probe", description="Simple readiness endpoint for container orchestration.")
def healthz():
    return {"status": "ok"}

@app.get("/health/redirect-uri", tags=["Health"], summary="Active Atlassian redirect URIs", description="Returns which redirect URIs are currently active for Jira and Confluence, for operator verification.")
def health_redirect_uri():
    return _ocean_response(get_active_redirect_uris_debug(), "active redirect URIs")

@app.get("/health/authorize-url", tags=["Health"], summary="Verification: Jira authorize URL (no redirect, no state)", description="Returns the Atlassian authorize URL that would be used by /auth/jira/login with default scopes and no state. Use this to verify the exact redirect_uri parameter.")
def health_authorize_url_probe(request: Request):
    cfg = get_jira_oauth_config()
    client_id = (cfg.get("client_id") or "").strip()
    redirect_uri = os.getenv("JIRA_REDIRECT_URI", "").strip()
    if not client_id or not redirect_uri:
        return _ocean_response({"url": None, "error": "missing_config", "client_id_present": bool(client_id), "redirect_uri_present": bool(redirect_uri)}, "oauth not configured")
    default_scopes = "read:jira-work read:jira-user offline_access"
    url = build_atlassian_authorize_url(client_id=client_id, redirect_uri=redirect_uri, scopes=default_scopes, state=None)
    encoded_ri = urllib.parse.quote(redirect_uri, safe="")
    return _ocean_response({"url": url, "redirect_uri": redirect_uri, "redirect_uri_encoded": encoded_ri}, "authorize url")

@app.get("/health/redirect-pieces", tags=["Health"], summary="Verification: Computed Jira redirect pieces", description="Returns the scheme, host:port and path used to form the Jira redirect_uri, honoring X-Forwarded headers.")
def health_redirect_pieces(request: Request):
    try:
        redirect_uri = os.getenv("JIRA_REDIRECT_URI", "").strip()
        source = "env"
        encoded = urllib.parse.quote(redirect_uri, safe="") if redirect_uri else ""
        parsed = urllib.parse.urlparse(redirect_uri) if redirect_uri else urllib.parse.urlparse("")
        return _ocean_response(
            {"scheme": parsed.scheme, "host_port": parsed.netloc, "path": parsed.path, "redirect_uri": redirect_uri, "redirect_uri_encoded": encoded, "source": source},
            "computed redirect pieces",
        )
    except Exception as e:
        return _ocean_response({"error": str(e)}, "failed to compute pieces")

# Include auth router last (contains csrf resolve, login, session, and redirect-only callback)
from src.api.auth import router as auth_router  # noqa: E402
app.include_router(auth_router)
