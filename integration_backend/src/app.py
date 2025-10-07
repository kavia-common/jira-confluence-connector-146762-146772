from __future__ import annotations

# Load .env and configure logging as early as possible
from src import startup  # noqa: F401

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

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

    # CORS: Use env-driven allowlist, and explicitly include the preview frontend origin.
    allowed_origins = get_cors_origins()

    # For simple GET to /auth/jira returning JSON, no credentials are required.
    # CORS must be added BEFORE route inclusion so responses include Access-Control-Allow-Origin.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "OPTIONS", "POST"],
        allow_headers=["*"],
    )

    # Routers (ensure /auth/jira and related endpoints are registered)
    app.include_router(health_router.router)
    app.include_router(oauth_router.router)
    app.include_router(oauth_return_router)

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

    logging.getLogger("startup").info(
        "App created via src.app:create_app; routers mounted. Visit GET /routes for route list."
    )
    return app

# PUBLIC_INTERFACE
app = create_app()
