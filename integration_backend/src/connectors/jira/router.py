from __future__ import annotations

from typing import List, Optional, Dict, Any

from fastapi import APIRouter, Query, Header
from fastapi import status as http_status

from ..base.models import SearchResultItem, CreateResult, ConnectionStatus
from ...db.token_store import get_tokens, delete_tokens
from ...api.errors import error_response
from .client import JiraClient

router = APIRouter(prefix="/connectors/jira", tags=["Connectors", "Jira"])


def _tenant(x_tenant_id: Optional[str], tenant_id_query: Optional[str]) -> str:
    return (x_tenant_id or tenant_id_query or "default").strip() or "default"


# PUBLIC_INTERFACE
@router.get("/status", response_model=ConnectionStatus, summary="Jira connection status", description="Returns connection status for the Jira connector for the given tenant.")
def get_status(x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"), tenant_id: Optional[str] = Query(default=None)):
    """Return connection status for Jira connector per tenant."""
    tenant = _tenant(x_tenant_id, tenant_id)
    rec = get_tokens("jira", tenant)
    return ConnectionStatus(
        connected=bool(rec),
        scopes=(rec or {}).get("scopes"),
        expires_at=(rec or {}).get("expires_at"),
        refreshed_at=(rec or {}).get("refreshed_at"),
        error=(rec or {}).get("last_error"),
    )


# PUBLIC_INTERFACE
@router.get("/projects", summary="List Jira projects", description="List Jira projects for authenticated tenant")
def list_projects(x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"), tenant_id: Optional[str] = Query(default=None)):
    """List Jira projects available to the tenant."""
    tenant = _tenant(x_tenant_id, tenant_id)
    client = JiraClient(tenant_id=tenant)
    projects = client.list_projects()
    return {"items": projects}


# PUBLIC_INTERFACE
@router.get("/search", response_model=List[SearchResultItem], summary="Search Jira", description="Search resources on Jira returning normalized items")
def search(q: str = Query(default="", description="Search JQL"), limit: int = Query(default=10, ge=1, le=25), filters: Optional[str] = Query(default=None, description="Optional JSON string of filter mapping"), x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"), tenant_id: Optional[str] = Query(default=None)):
    """Search Jira with JQL and normalize results."""
    tenant = _tenant(x_tenant_id, tenant_id)
    client = JiraClient(tenant_id=tenant)
    jql = q or ""
    items = client.search_jql(jql=jql, limit=limit)
    return [SearchResultItem(**i) for i in items]


# PUBLIC_INTERFACE
@router.post("/create", response_model=CreateResult, summary="Create Jira resource", description="Create a Jira resource using a generic payload and return a normalized result (requires connection).")
def create_resource(payload: Dict[str, Any], x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"), tenant_id: Optional[str] = Query(default=None)):
    """Create a Jira issue using normalized request payload."""
    tenant = _tenant(x_tenant_id, tenant_id)
    resource = payload.get("resource")
    if resource != "issue":
        raise error_response("VALIDATION_ERROR", "Only resource=issue is supported", status_code=http_status.HTTP_400_BAD_REQUEST)
    project_key = payload.get("project_key")
    summary = payload.get("summary")
    description = payload.get("description")
    if not project_key or not summary:
        raise error_response("VALIDATION_ERROR", "project_key and summary are required", status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY)
    client = JiraClient(tenant_id=tenant)
    result = client.create_issue(project_key=project_key, summary=summary, description=description)
    return CreateResult(id=result["id"], url=result.get("url"), title=result.get("title"), metadata=result.get("metadata", {}))


# PUBLIC_INTERFACE
@router.delete("/connection", summary="Delete Jira connection", description="Revoke/purge Jira tokens for tenant")
def delete_connection(x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"), tenant_id: Optional[str] = Query(default=None)):
    """Purge Jira tokens for the tenant in the local store."""
    tenant = _tenant(x_tenant_id, tenant_id)
    delete_tokens("jira", tenant)
    return {"status": "ok"}


# PUBLIC_INTERFACE
@router.patch("/connection", summary="Update Jira connection", description="Update Jira site/base URL if needed")
def patch_connection(body: Dict[str, Any], x_tenant_id: Optional[str] = Header(default=None, alias="X-Tenant-Id"), tenant_id: Optional[str] = Query(default=None)):
    """Update the base URL for the Jira tenant connection."""
    tenant = _tenant(x_tenant_id, tenant_id)
    base_url = body.get("base_url")
    if not base_url:
        raise error_response("VALIDATION_ERROR", "base_url is required", status_code=http_status.HTTP_422_UNPROCESSABLE_ENTITY)
    from ...db.token_store import update_meta as update_meta_store
    update_meta_store("jira", tenant, base_url=base_url)
    return {"status": "ok", "base_url": base_url}
