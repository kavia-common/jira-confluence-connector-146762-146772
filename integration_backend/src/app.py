from __future__ import annotations

# Load .env and configure logging as early as possible
from src import startup  # noqa: F401

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import os

from src.api import oauth_atlassian as oauth_router
from src.api import health as health_router
from src.api.oauth_settings import get_cors_origins
from src.api.oauth_return_flow import router as oauth_return_router

openapi_tags = [
    {"name": "Health", "description": "Health and readiness checks."},
    {"name": "Users", "description": "Manage users who connect JIRA/Confluence."},
    {"name": "JIRA Projects", "description": "Manage synced JIRA projects."},
    {"name": "Confluence Pages", "description": "Manage synced Confluence pages."},
    {"name": "Integrations", "description": "Connect and fetch from JIRA/Confluence (placeholders)."},
    {"name": "Auth", "description": "OAuth 2.0 authorization flows for Atlassian (Jira/Confluence)."},
]

# PUBLIC_INTERFACE
def create_app() -> FastAPI:
    """Create and configure the FastAPI app.

    Notes:
        - Includes oauth_atlassian router which defines:
          GET /auth/jira -> returns JSON {url} to begin Jira OAuth,
          GET /auth/jira/login (legacy shim), GET /api/auth/jira/login (alias),
          GET /api/oauth/atlassian/login (PKCE), and diagnostics like GET /routes.
        - The frontend can call GET /auth/jira to fetch the authorize URL and then redirect the browser.
    """
    app = FastAPI(
        title="Jira-Confluence Integration API",
        description="Backend API for integrating JIRA and Confluence, with a lightweight persistence layer.",
        version="0.1.0",
        openapi_tags=openapi_tags,
    )

    # Resolve allowed origins from environment with required explicit frontend origin support.
    # Use get_cors_origins() (includes BACKEND_CORS_ORIGINS, FRONTEND_BASE_URL, NEXT_PUBLIC_FRONTEND_BASE_URL),
    # then ensure defaults if unset and include the explicitly requested preview origin when configured.
    configured_origins = get_cors_origins()
    if not configured_origins:
        configured_origins = ["http://localhost:3000"]

    # If env defines NEXT_PUBLIC_FRONTEND_BASE_URL or FRONTEND_BASE_URL, append exact values.
    for key in ("NEXT_PUBLIC_FRONTEND_BASE_URL", "FRONTEND_BASE_URL"):
        v = os.getenv(key, "").strip().rstrip("/")
        if v and v not in configured_origins:
            configured_origins.append(v)

    # Explicitly include the preview frontend origin if provided via BACKEND_CORS_ORIGINS; otherwise ensure it's present only if relevant.
    # Note: We must not add '*' when allow_credentials=True.
    # The instructions require the exact frontend origin to be included:
    required_preview_origin = "https://vscode-internal-18211-beta.beta01.cloud.kavia.ai:4000"
    if required_preview_origin not in configured_origins:
        # Only include this explicit preview origin as a safety net; harmless if backend isn't running there.
        configured_origins.append(required_preview_origin)

    # CORS must be added BEFORE route inclusion so responses (including redirects) include CORS headers.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=configured_origins,
        allow_credentials=True,  # OAuth flow uses httpOnly cookie 'sid'
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["*"],
        max_age=600,
    )

    # Routers (ensure /auth/jira and related endpoints are registered)
    app.include_router(health_router.router)
    app.include_router(oauth_router.router)
    app.include_router(oauth_return_router)

    # Also include /auth/status from a small dedicated router (kept modular)
    try:
        from src.api.auth_status import router as auth_status_router  # local import to avoid import-time cycles
        app.include_router(auth_status_router)
    except Exception as e:
        logging.getLogger("startup").warning("Failed to include auth_status router: %s", e)

    # PUBLIC_INTERFACE
    @app.get(
        "/auth/jira",
        tags=["Auth"],
        summary="Get Jira OAuth authorization URL (JSON) (app passthrough)",
        description="Returns JSON { url } with the Atlassian authorize URL. Mirrors router handler to ensure availability at app level.",
    )
    async def _auth_jira_json_passthrough(state: str | None = None, scope: str | None = None):
        """Ensures GET /auth/jira JSON endpoint is present at the app level."""
        logging.getLogger("auth").info("Hit /auth/jira passthrough; forwarding to router handler.")
        return await oauth_router.jira_get_oauth_url(state=state, scope=scope)

    # Provide an explicit pass-through route to guarantee /auth/jira/login exists at app-level
    # even if router import order changes in future refactors.
    # PUBLIC_INTERFACE
    @app.get(
        "/auth/jira/login",
        tags=["Auth"],
        summary="Start Jira OAuth 2.0 login (app passthrough)",
        description="Pass-through to oauth router legacy shim to redirect to Atlassian authorization.",
    )
    async def _auth_jira_login_passthrough(state: str | None = None, scope: str | None = None):
        """Ensures GET /auth/jira/login is always present on the app."""
        logging.getLogger("auth").info("Hit /auth/jira/login passthrough; forwarding to router handler.")
        # Defer to router implementation to build the redirect URL consistently
        return await oauth_router.jira_login_legacy(state=state, scope=scope)

    # PUBLIC_INTERFACE
    @app.get(
        "/auth/status",
        tags=["Auth"],
        summary="Connection status (lightweight)",
        description="Returns basic connection status. For now, returns { connected: false } unless future session logic indicates true.",
    )
    async def auth_status():
        """Lightweight status endpoint so the frontend can determine basic connectivity."""
        # In future, inspect a session/cookie to determine true connection status.
        return {"connected": False}

    # Log resolved CORS origins at startup
    logging.getLogger("startup").info("CORS configured with allow_credentials=True; allowed_origins=%s", configured_origins)
    logging.getLogger("startup").info(
        "App created via src.app:create_app; routers mounted. Visit GET /routes for route list."
    )
    return app

# PUBLIC_INTERFACE
app = create_app()

# PUBLIC_INTERFACE
def run():
    """Convenience runner for local/CI.

    Reads:
        PORT: Optional port to bind (default: 3001)
        HOST: Optional host to bind (default: 0.0.0.0)

    Starts uvicorn against src.app:app.
    """
    import uvicorn

    port = int(os.getenv("PORT", "3001"))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("src.app:app", host=host, port=port, reload=False)
