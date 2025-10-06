from __future__ import annotations

# Load .env and configure logging as early as possible
from src import startup  # noqa: F401

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging

from src.api.oauth_settings import get_cors_origins
from src.api import oauth_atlassian as oauth_router
from src.api import health as health_router

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
          GET /auth/jira/login (legacy shim), GET /api/auth/jira/login (alias),
          GET /api/oauth/atlassian/login (PKCE), and diagnostics like GET /routes.
        - The frontend should call GET /auth/jira/login to start Jira OAuth.
    """
    app = FastAPI(
        title="Jira-Confluence Integration API",
        description="Backend API for integrating JIRA and Confluence, with a lightweight persistence layer.",
        version="0.1.0",
        openapi_tags=openapi_tags,
    )

    # CORS
    origins = get_cors_origins()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Routers
    app.include_router(health_router.router)
    app.include_router(oauth_router.router)

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

    logging.getLogger("startup").info("App created via src.app:create_app; routers mounted. Visit GET /routes for route list.")
    return app

# PUBLIC_INTERFACE
app = create_app()
