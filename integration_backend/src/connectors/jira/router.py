from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse

from src.connectors.base.models import SearchResultItem, CreateResult, ConnectionStatus
from src.connectors.jira.impl import JiraConnector
from src.db.config import get_db

router = APIRouter(prefix="/jira", tags=["Connectors", "Jira"])


def _resolve_tenant_id(request: Request, tenant_id_qs: Optional[str]) -> str:
    # Resolve tenant from header or query param; fallback to 'default'
    tenant = request.headers.get("X-Tenant-Id") or tenant_id_qs or "default"
    return tenant.strip()


# PUBLIC_INTERFACE
@router.get(
    "/status",
    response_model=ConnectionStatus,
    summary="Jira connection status",
    description="Returns connection status for the Jira connector for the given tenant.",
)
def get_status(request: Request, db=Depends(get_db), tenant_id: Optional[str] = Query(None)) -> ConnectionStatus:
    """Return whether the tenant is connected to Jira, with scope/expiry info if known."""
    connector = JiraConnector().with_db(db)
    tenant = _resolve_tenant_id(request, tenant_id)
    return connector.connection_status(tenant)


# PUBLIC_INTERFACE
@router.get(
    "/search",
    response_model=List[SearchResultItem],
    summary="Search Jira",
    description="Search resources on Jira returning normalized items (stubbed without live token).",
)
def search(
    request: Request,
    q: str = Query("", description="Search query"),
    limit: int = Query(10, ge=1, le=25),
    filters: Optional[str] = Query(None, description="Optional JSON string of filter mapping"),
    tenant_id: Optional[str] = Query(None),
    db=Depends(get_db),
) -> List[SearchResultItem]:
    """Search Jira and return normalized items."""
    connector = JiraConnector().with_db(db)
    tenant = _resolve_tenant_id(request, tenant_id)
    filters_obj: Optional[Dict[str, Any]] = None
    if filters:
        try:
            import json

            filters_obj = json.loads(filters)
        except Exception:
            filters_obj = None
    return connector.search(query=q, tenant_id=tenant, limit=limit, filters=filters_obj)


# PUBLIC_INTERFACE
@router.post(
    "/create",
    response_model=CreateResult,
    summary="Create Jira resource",
    description="Create a Jira resource using a generic payload and return a normalized result (requires connection).",
)
def create_resource(
    request: Request,
    payload: Dict[str, Any],
    tenant_id: Optional[str] = Query(None),
    db=Depends(get_db),
) -> CreateResult:
    """Create a new Jira resource for the tenant (requires valid connection)."""
    connector = JiraConnector().with_db(db)
    tenant = _resolve_tenant_id(request, tenant_id)
    return connector.create(payload=payload, tenant_id=tenant)


# PUBLIC_INTERFACE
@router.get(
    "/oauth/login",
    summary="Start Jira OAuth",
    description="Returns JSON authorize URL by default; add ?redirect=true for 307 redirect.",
)
def oauth_login(
    request: Request,
    tenant_id: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    scopes: Optional[str] = Query(None),
    redirect: Optional[bool] = Query(False),
    db=Depends(get_db),
):
    """Initiate Jira OAuth for a tenant. Returns URL or performs 307 redirect."""
    connector = JiraConnector().with_db(db)
    tenant = _resolve_tenant_id(request, tenant_id)

    # Generate backend CSRF state and embed client-provided state as hint
    import json as _json
    from src.api.main import _gen_csrf_state, _sign_state, _STATE_COOKIE_NAME, _STATE_COOKIE_TTL  # reuse helpers

    csrf_raw = _gen_csrf_state()
    signed_csrf = _sign_state(csrf_raw)
    compound_state_obj = {"csrf": signed_csrf, "tenant_id": tenant}
    if state:
        compound_state_obj["client"] = state
    compound_state = _json.dumps(compound_state_obj, separators=(",", ":"))

    url = connector.oauth_authorize_url(tenant_id=tenant, state=compound_state, scopes=scopes)
    if redirect:
        response = RedirectResponse(url=url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
        response.headers["Cache-Control"] = "no-store"
        response.set_cookie(
            key=_STATE_COOKIE_NAME,
            value=signed_csrf,
            max_age=_STATE_COOKIE_TTL,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
        )
        # lightweight debug indicator to confirm cookie set when using connectors route
        try:
            from src.api.main import _log_event
            _log_event(20, "oauth_state_cookie_set", request, provider="jira", cookie=_STATE_COOKIE_NAME, router="connectors")
        except Exception:
            pass
        return response
    resp = JSONResponse(status_code=200, content={"url": url})
    resp.set_cookie(
        key=_STATE_COOKIE_NAME,
        value=signed_csrf,
        max_age=_STATE_COOKIE_TTL,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )
    try:
        from src.api.main import _log_event
        _log_event(20, "oauth_state_cookie_set", request, provider="jira", cookie=_STATE_COOKIE_NAME, router="connectors", mode="json")
    except Exception:
        pass
    return resp


# PUBLIC_INTERFACE
@router.get(
    "/oauth/callback",
    response_model=ConnectionStatus,
    summary="Jira OAuth callback (connector)",
    description="Processes OAuth code and stores tokens under the resolved tenant.",
)
def oauth_callback(
    request: Request,
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    tenant_id: Optional[str] = Query(None),
    db=Depends(get_db),
) -> ConnectionStatus:
    """Exchange authorization code for tokens and persist them for the tenant."""
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    # Strict state validation using backend cookie/signature to prevent CSRF
    cookie_state = request.cookies.get("jira_oauth_state")
    if not state:
        raise HTTPException(status_code=422, detail="Missing state parameter")
    csrf_from_state: Optional[str] = None
    try:
        import json as _json
        parsed = _json.loads(state)
        if isinstance(parsed, dict):
            csrf_from_state = parsed.get("csrf") if isinstance(parsed.get("csrf"), str) else None
    except Exception:
        csrf_from_state = None
    if not csrf_from_state:
        raise HTTPException(status_code=422, detail="Invalid state format")
    from src.api.main import _verify_signed_state as _vss
    import hmac as _hmac
    if not cookie_state or not _vss(csrf_from_state) or not _hmac.compare_digest(str(cookie_state), str(csrf_from_state)):
        raise HTTPException(status_code=422, detail="State mismatch")

    tenant = _resolve_tenant_id(request, tenant_id)
    # If state carries a tenant hint, prefer that.
    try:
        import json
        j = json.loads(state)
        if isinstance(j, dict) and j.get("tenant_id"):
            tenant = j.get("tenant_id")
    except Exception:
        pass

    connector = JiraConnector().with_db(db)
    return connector.oauth_callback(code=code, tenant_id=tenant, state=state)


# PUBLIC_INTERFACE
@router.get(
    "/resource/{key}",
    summary="Get Jira resource by key",
    description="Fetch a Jira resource by key or id. Stubbed in scaffolding phase.",
)
def get_resource(
    request: Request, key: str, tenant_id: Optional[str] = Query(None), db=Depends(get_db)
) -> Dict[str, Any]:
    """Return a stubbed resource for now."""
    connector = JiraConnector().with_db(db)
    tenant = _resolve_tenant_id(request, tenant_id)
    return connector.get_resource(key=key, tenant_id=tenant)
