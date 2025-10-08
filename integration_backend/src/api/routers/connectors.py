from __future__ import annotations

from fastapi import APIRouter

from src.connectors.jira.router import router as jira_router
from src.connectors.confluence.router import router as confluence_router

# PUBLIC_INTERFACE
connectors_router = APIRouter(
    prefix="/connectors",
    tags=["Connectors"],
    responses={404: {"description": "Connector route not found"}},
)

# Mount per-connector routers
connectors_router.include_router(jira_router)
connectors_router.include_router(confluence_router)
