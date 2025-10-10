from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Header

from ...db.token_store import get_tokens
from ...connectors.jira.router import router as jira_router
from ...connectors.confluence.router import router as confluence_router

connectors_router = APIRouter(prefix="/connectors", tags=["Connectors"])

connectors_router.include_router(jira_router)
connectors_router.include_router(confluence_router)


# PUBLIC_INTERFACE
@connectors_router.get("", summary="List available connectors with status", description="List available connectors and per-tenant status (connected, scopes, expires_at, refreshed_at, last_error).")
def list_connectors(x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id")):
    """List installed connectors and show per-tenant status."""
    tenant = (x_tenant_id or "default").strip() or "default"
    jira = get_tokens("jira", tenant) or {}
    conf = get_tokens("confluence", tenant) or {}

    def norm(rec):
        return {
            "connected": bool(rec),
            "scopes": rec.get("scopes"),
            "expires_at": rec.get("expires_at"),
            "refreshed_at": rec.get("refreshed_at"),
            "last_error": rec.get("last_error"),
        }

    return {
        "connectors": [
            {"id": "jira", "status": norm(jira)},
            {"id": "confluence", "status": norm(conf)},
        ]
    }
