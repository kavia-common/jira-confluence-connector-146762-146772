from __future__ import annotations

# Load .env and configure logging as early as possible
from src import startup  # noqa: F401

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request as StarletteRequest

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
    def list_routes(request: StarletteRequest):
        """
        Enumerate and return all registered routes for diagnostics.

        Returns:
            List of routes with method(s), path, name, and tags (if available).
        """
        app_obj = request.app
        items = []
        for r in app_obj.routes:
            methods = sorted(getattr(r, "methods", []) or [])
            methods = [m for m in methods if m not in ("HEAD", "OPTIONS")]
            name = getattr(r, "name", "")
            path = getattr(r, "path", "")
            tags = []
            try:
                r_tags = getattr(r, "tags", None) or []
                tags = list(r_tags)
            except Exception:
                tags = []
            items.append(
                {
                    "path": path,
                    "methods": methods,
                    "name": name,
                    "tags": tags,
                }
            )
        items.sort(key=lambda x: (x["path"], ",".join(x["methods"])))
        return JSONResponse(items)

    return app

# PUBLIC_INTERFACE
app = create_app()
