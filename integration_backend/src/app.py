from __future__ import annotations

# Load .env and configure logging as early as possible
from src import startup  # noqa: F401

from typing import Optional, List
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse

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
    """Create and configure the FastAPI app."""
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

    # PUBLIC_INTERFACE
    @app.get(
        "/routes",
        tags=["Health"],
        summary="List registered routes",
        description="Diagnostic endpoint: lists all registered routes and methods.",
    )
    def list_routes() -> List[dict]:
        """Return all registered routes for diagnostics."""
        routes = []
        for r in app.routes:
            try:
                path = getattr(r, "path", "")
                methods = sorted(list(getattr(r, "methods", set())))
                name = getattr(r, "name", "")
                routes.append({"path": path, "methods": methods, "name": name})
            except Exception:
                continue
        return routes

    # PUBLIC_INTERFACE
    @app.get(
        "/auth",
        tags=["Auth"],
        summary="Auth routes index",
        description="Minimal index listing available auth endpoints.",
    )
    def auth_index():
        """Provide a simple index of auth-related endpoints for quick verification."""
        return JSONResponse(
            {
                "auth_routes": [
                    "/auth/jira/login",
                    "/api/oauth/atlassian/login",
                    "/api/oauth/callback/atlassian",
                    "/api/oauth/atlassian/refresh",
                    "/api/atlassian/resources",
                ]
            }
        )

    # PUBLIC_INTERFACE
    @app.get(
        "/auth/jira/login",
        tags=["Auth"],
        summary="Start Jira OAuth (shim to PKCE)",
        description="Shim endpoint that redirects to /api/oauth/atlassian/login. Accepts return_url and maps it to redirect param.",
    )
    def jira_login_shim(state: Optional[str] = None, scope: Optional[str] = None, return_url: Optional[str] = None):
        """Legacy-compatible Jira login path that redirects to the PKCE login path."""
        params = []
        if state:
            params.append(f"state={state}")
        if scope:
            # pass through as-is; PKCE handler will honor or use defaults
            from urllib.parse import quote_plus
            params.append(f"scope={quote_plus(scope)}")
        if return_url:
            from urllib.parse import quote_plus
            # map return_url -> redirect for PKCE handler
            params.append(f"redirect={quote_plus(return_url)}")
        query = ("?" + "&".join(params)) if params else ""
        return RedirectResponse(f"/api/oauth/atlassian/login{query}", status_code=307)

    # PUBLIC_INTERFACE
    @app.get(
        "/",
        tags=["Health"],
        summary="Service index",
        description="Service root index with helpful links.",
    )
    def root_index():
        """Simple root index to help navigate and verify routes."""
        return JSONResponse(
            {
                "message": "integration_backend running",
                "docs": "/docs",
                "openapi": "/openapi.json",
                "routes": "/routes",
                "auth_index": "/auth",
            }
        )

    return app


# PUBLIC_INTERFACE
app = create_app()
