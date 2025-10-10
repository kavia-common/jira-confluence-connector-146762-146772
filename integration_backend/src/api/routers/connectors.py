from typing import Any, Dict, List, Optional, Tuple
import time
import json
import os
import logging
from fastapi import APIRouter, Header, Query, Body
from pydantic import BaseModel, Field
from ..schemas import SearchResultItem, CreateResult, ConnectionStatus
from ..errors import http_error, ErrorCode, ErrorResponse, map_vendor_error
from ...db.token_store import TokenStore
from ...connectors.jira.client import JiraClient, JiraClientError, JiraAuth
from ...connectors.confluence.impl import ConfluenceClient, ConfluenceClientError

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/connectors", tags=["Connectors"])

DEFAULT_TTL_SKEW = 120  # seconds before expiry to refresh
ENABLE_PAT = os.getenv("ENABLE_JIRA_PAT", "false").lower() in ("1", "true", "yes")
ENABLE_PKCE = os.getenv("ENABLE_OAUTH_PKCE", "false").lower() in ("1", "true", "yes")

# Simple OAuth state validation scaffolding
class OAuthState(BaseModel):
    """Scaffold for backend-generated OAuth state."""
    csrf: str
    tenant: Optional[str] = None
    nonce: Optional[str] = None


def _tenant(tenant_header: Optional[str]) -> str:
    if tenant_header and tenant_header.strip():
        return tenant_header.strip()
    # Fallback to single-tenant default
    return "default"


def _status_from_store(store: TokenStore, tenant_id: str, provider: str) -> ConnectionStatus:
    rec = store.get_token(tenant_id, provider)
    if not rec:
        return ConnectionStatus(connected=False, scopes=None, expires_at=None, refreshed_at=None, error=None)
    return ConnectionStatus(
        connected=True if rec.get("access_token") or rec.get("pat") else False,
        scopes=rec.get("scopes"),
        expires_at=rec.get("expires_at"),
        refreshed_at=rec.get("refreshed_at"),
        error=rec.get("last_error"),
    )


# PUBLIC_INTERFACE
@router.get(
    "",
    summary="List available connectors with status",
    response_model=List[Dict[str, Any]],
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
)
def list_connectors(x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id")) -> List[Dict[str, Any]]:
    """List available connectors and per-tenant status."""
    tenant_id = _tenant(x_tenant_id)
    store = TokenStore()
    items = []
    for provider in ["jira", "confluence"]:
        status = _status_from_store(store, tenant_id, provider)
        items.append(
            {
                "id": provider,
                "title": provider.capitalize(),
                "connected": status.connected,
                "scopes": status.scopes,
                "expires_at": status.expires_at,
                "refreshed_at": status.refreshed_at,
                "last_error": status.error,
            }
        )
    return items


# PUBLIC_INTERFACE
@router.get(
    "/{provider}/connection",
    summary="Get connection details",
    response_model=ConnectionStatus,
    responses={404: {"model": ErrorResponse}},
)
def get_connection(provider: str, x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id")) -> ConnectionStatus:
    """Get connection status for the provider and tenant."""
    if provider not in ("jira", "confluence"):
        raise http_error(404, ErrorCode.NOT_FOUND, "Unknown provider")
    tenant_id = _tenant(x_tenant_id)
    store = TokenStore()
    return _status_from_store(store, tenant_id, provider)


class ConnectionPatch(BaseModel):
    """Update connection settings or rotate tokens."""
    base_url: Optional[str] = Field(None, description="Base site URL for the provider")
    rotate: Optional[bool] = Field(False, description="Rotate access token if supported (OAuth)")
    pat: Optional[str] = Field(None, description="Optional PAT/API key (env gated for Jira)")

# PUBLIC_INTERFACE
@router.patch(
    "/{provider}/connection",
    summary="Update connection",
    response_model=Dict[str, Any],
    responses={400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
def patch_connection(
    provider: str,
    payload: ConnectionPatch = Body(...),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
) -> Dict[str, Any]:
    """Update site/base URL or rotate tokens; for Jira also save PAT if enabled."""
    if provider not in ("jira", "confluence"):
        raise http_error(404, ErrorCode.NOT_FOUND, "Unknown provider")
    tenant_id = _tenant(x_tenant_id)
    store = TokenStore()
    rec = store.get_token(tenant_id, provider) or {}

    if payload.base_url:
        rec["base_url"] = payload.base_url

    if provider == "jira" and payload.pat is not None:
        if not ENABLE_PAT:
            raise http_error(400, ErrorCode.VALIDATION, "PAT not allowed (ENABLE_JIRA_PAT disabled)")
        rec["pat"] = payload.pat
        logger.info("Saved Jira PAT for tenant=%s (masked)", tenant_id)

    # Rotate token simple stub: clear expiry to force refresh on next call
    if payload.rotate:
        if "refresh_token" in rec:
            rec["expires_at"] = 0
            rec["refreshed_at"] = int(time.time())
        else:
            logger.info("Rotate requested but no refresh_token available for provider=%s", provider)

    store.save_token(tenant_id, provider, rec)
    return {"ok": True, "provider": provider, "status": _status_from_store(store, tenant_id, provider).dict()}


# PUBLIC_INTERFACE
@router.delete(
    "/{provider}/connection",
    summary="Delete connection",
    response_model=Dict[str, Any],
    responses={404: {"model": ErrorResponse}},
)
def delete_connection(provider: str, x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id")) -> Dict[str, Any]:
    """Revoke/purge stored tokens for provider and tenant."""
    if provider not in ("jira", "confluence"):
        raise http_error(404, ErrorCode.NOT_FOUND, "Unknown provider")
    tenant_id = _tenant(x_tenant_id)
    store = TokenStore()
    store.delete_token(tenant_id, provider)
    return {"ok": True}


def _jira_auth_for_tenant(store: TokenStore, tenant_id: str) -> Tuple[JiraAuth, Dict[str, Any]]:
    rec = store.get_token(tenant_id, "jira")
    if not rec:
        raise http_error(400, ErrorCode.NOT_CONNECTED, "Jira not connected for tenant")
    auth = JiraAuth(
        access_token=rec.get("access_token"),
        refresh_token=rec.get("refresh_token"),
        expires_at=rec.get("expires_at"),
        base_url=rec.get("base_url") or os.getenv("NEXT_PUBLIC_ATLASSIAN_CLOUD_BASE_URL", ""),
        pat=rec.get("pat") if ENABLE_PAT else None,
    )
    return auth, rec


def _save_jira_auth(store: TokenStore, tenant_id: str, rec: Dict[str, Any], auth: JiraAuth) -> None:
    rec.update(
        {
            "access_token": auth.access_token,
            "refresh_token": auth.refresh_token,
            "expires_at": auth.expires_at,
            "refreshed_at": int(time.time()),
        }
    )
    store.save_token(tenant_id, "jira", rec)


# PUBLIC_INTERFACE
@router.get(
    "/jira/projects",
    summary="List Jira projects",
    description="List Jira projects for authenticated tenant",
    response_model=List[Dict[str, Any]],
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def list_jira_projects(
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
    limit: int = Query(25, ge=1, le=50),
    cursor: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    tenant_id = _tenant(x_tenant_id)
    store = TokenStore()
    auth, rec = _jira_auth_for_tenant(store, tenant_id)
    client = JiraClient(auth=auth, enable_pkce=ENABLE_PKCE)
    try:
        refreshed = client.refresh_token_if_needed(DEFAULT_TTL_SKEW)
        if refreshed:
            _save_jira_auth(store, tenant_id, rec, client.auth)
        data = client.list_projects(limit=limit, cursor=cursor)
        return data.get("items", [])
    except JiraClientError as e:
        # Retry on 401 once with refresh
        if e.status == 401 and client.try_refresh_on_unauthorized():
            _save_jira_auth(store, tenant_id, rec, client.auth)
            try:
                data = client.list_projects(limit=limit, cursor=cursor)
                return data.get("items", [])
            except JiraClientError as e2:
                raise map_vendor_error(e2)
        raise map_vendor_error(e)


# PUBLIC_INTERFACE
@router.get(
    "/jira/search",
    summary="Search Jira",
    description="Search resources on Jira returning normalized items",
    response_model=List[SearchResultItem],
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def search_jira(
    q: str = Query("", description="Search JQL"),
    limit: int = Query(10, ge=1, le=25),
    filters: Optional[str] = Query(None, description="Optional JSON string of filter mapping"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
) -> List[SearchResultItem]:
    tenant_id = _tenant(x_tenant_id)
    store = TokenStore()
    auth, rec = _jira_auth_for_tenant(store, tenant_id)
    client = JiraClient(auth=auth, enable_pkce=ENABLE_PKCE)
    parsed_filters: Dict[str, Any] = {}
    if filters:
        try:
            parsed_filters = json.loads(filters)
        except Exception:
            raise http_error(400, ErrorCode.VALIDATION, "Invalid filters JSON")

    try:
        refreshed = client.refresh_token_if_needed(DEFAULT_TTL_SKEW)
        if refreshed:
            _save_jira_auth(store, tenant_id, rec, client.auth)
        results = client.search(q=q, limit=limit, filters=parsed_filters)
        return [SearchResultItem(**item) for item in results]
    except JiraClientError as e:
        if e.status == 401 and client.try_refresh_on_unauthorized():
            _save_jira_auth(store, tenant_id, rec, client.auth)
            try:
                results = client.search(q=q, limit=limit, filters=parsed_filters)
                return [SearchResultItem(**item) for item in results]
            except JiraClientError as e2:
                raise map_vendor_error(e2)
        raise map_vendor_error(e)


# PUBLIC_INTERFACE
@router.post(
    "/jira/create",
    summary="Create Jira resource",
    description="Create a Jira resource using a generic payload and return a normalized result (requires connection).",
    response_model=CreateResult,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 429: {"model": ErrorResponse}},
)
def create_jira_resource(
    payload: Dict[str, Any] = Body(...),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
) -> CreateResult:
    tenant_id = _tenant(x_tenant_id)
    store = TokenStore()
    auth, rec = _jira_auth_for_tenant(store, tenant_id)
    client = JiraClient(auth=auth, enable_pkce=ENABLE_PKCE)

    try:
        refreshed = client.refresh_token_if_needed(DEFAULT_TTL_SKEW)
        if refreshed:
            _save_jira_auth(store, tenant_id, rec, client.auth)
        res = client.create(payload)
        return CreateResult(**res)
    except JiraClientError as e:
        if e.status == 401 and client.try_refresh_on_unauthorized():
            _save_jira_auth(store, tenant_id, rec, client.auth)
            try:
                res = client.create(payload)
                return CreateResult(**res)
            except JiraClientError as e2:
                raise map_vendor_error(e2)
        raise map_vendor_error(e)


# Minimal Confluence endpoints (list spaces, search, create stubs using stored tokens)
# PUBLIC_INTERFACE
@router.get(
    "/confluence/spaces",
    summary="List Confluence spaces",
    description="List Confluence spaces for authenticated tenant (minimal).",
    response_model=List[Dict[str, Any]],
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}},
)
def list_confluence_spaces(
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
    limit: int = Query(25, ge=1, le=50),
    cursor: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    tenant_id = _tenant(x_tenant_id)
    store = TokenStore()
    rec = store.get_token(tenant_id, "confluence")
    if not rec:
        raise http_error(400, ErrorCode.NOT_CONNECTED, "Confluence not connected for tenant")
    client = ConfluenceClient(
        access_token=rec.get("access_token"),
        refresh_token=rec.get("refresh_token"),
        expires_at=rec.get("expires_at"),
        base_url=rec.get("base_url"),
    )
    try:
        items = client.list_spaces(limit=limit, cursor=cursor).get("items", [])
        return items
    except ConfluenceClientError as e:
        raise map_vendor_error(e)


# PUBLIC_INTERFACE
@router.get(
    "/confluence/search",
    summary="Search Confluence",
    description="Search resources on Confluence returning normalized items (stub if no live token).",
    response_model=List[SearchResultItem],
    responses={400: {"model": ErrorResponse}},
)
def search_confluence(
    q: str = Query("", description="Search query"),
    limit: int = Query(10, ge=1, le=25),
    filters: Optional[str] = Query(None, description="Optional JSON string of filter mapping"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
) -> List[SearchResultItem]:
    tenant_id = _tenant(x_tenant_id)
    store = TokenStore()
    rec = store.get_token(tenant_id, "confluence")
    if not rec:
        # Minimal stubbed response to keep the flow working.
        return []
    client = ConfluenceClient(
        access_token=rec.get("access_token"),
        refresh_token=rec.get("refresh_token"),
        expires_at=rec.get("expires_at"),
        base_url=rec.get("base_url"),
    )
    try:
        items = client.search(q=q, limit=limit)
        return [SearchResultItem(**i) for i in items]
    except ConfluenceClientError as e:
        raise map_vendor_error(e)


# PUBLIC_INTERFACE
@router.post(
    "/confluence/create",
    summary="Create Confluence resource",
    description="Create a Confluence resource; minimal stub implementation.",
    response_model=CreateResult,
    responses={400: {"model": ErrorResponse}},
)
def create_confluence_resource(
    payload: Dict[str, Any] = Body(...),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
) -> CreateResult:
    tenant_id = _tenant(x_tenant_id)
    store = TokenStore()
    rec = store.get_token(tenant_id, "confluence")
    if not rec:
        raise http_error(400, ErrorCode.NOT_CONNECTED, "Confluence not connected for tenant")
    client = ConfluenceClient(
        access_token=rec.get("access_token"),
        refresh_token=rec.get("refresh_token"),
        expires_at=rec.get("expires_at"),
        base_url=rec.get("base_url"),
    )
    try:
        created = client.create(payload)
        return CreateResult(**created)
    except ConfluenceClientError as e:
        raise map_vendor_error(e)


# Kavia tool exposure hooks (adapters) - minimal scaffolding
class ToolCall(BaseModel):
    """Kavia tool adapter call payload."""
    tool: str
    args: Dict[str, Any] = Field(default_factory=dict)


# PUBLIC_INTERFACE
@router.post(
    "/tools/invoke",
    summary="Invoke a connector tool (scaffold)",
    description="Minimal adapter for Kavia tool runtime to call connector operations.",
    response_model=Dict[str, Any],
    responses={400: {"model": ErrorResponse}},
)
def invoke_tool(payload: ToolCall, x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id")) -> Dict[str, Any]:
    tenant_id = _tenant(x_tenant_id)
    if payload.tool == "jira.search":
        return {"items": search_jira(q=payload.args.get("q", ""), limit=payload.args.get("limit", 10), x_tenant_id=tenant_id)}  # type: ignore
    if payload.tool == "jira.create":
        return create_jira_resource(payload=payload.args, x_tenant_id=tenant_id)  # type: ignore
    if payload.tool == "jira.projects":
        return {"items": list_jira_projects(x_tenant_id=tenant_id)}  # type: ignore
    if payload.tool == "confluence.search":
        return {"items": search_confluence(q=payload.args.get("q", ""), limit=payload.args.get("limit", 10), x_tenant_id=tenant_id)}  # type: ignore
    if payload.tool == "confluence.spaces":
        return {"items": list_confluence_spaces(x_tenant_id=tenant_id)}  # type: ignore
    raise http_error(400, ErrorCode.VALIDATION, f"Unknown tool '{payload.tool}'")
