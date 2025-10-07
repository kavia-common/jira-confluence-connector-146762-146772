from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from typing import List, Optional
import time
import urllib.parse
import httpx
import logging

from src.db.service import (
    create_user,
    list_users,
    get_user_by_id,
    upsert_jira_project,
    list_jira_projects_for_user,
    upsert_confluence_page,
    list_confluence_pages_for_user,
)
from src.api.oauth_config import (
    get_jira_oauth_config,
    get_frontend_base_url_default,
)
from src.api.schemas import (
    UserCreate,
    UserRead,
    JiraProjectCreate,
    JiraProjectRead,
    ConfluencePageCreate,
    ConfluencePageRead,
    JiraProjectsFetchResponse,
    ConfluencePagesFetchResponse,
)
from src.db.config import get_db

# Define a router to avoid creating a second FastAPI app instance
router = APIRouter()

def _ocean_response(data, message: str = "ok"):
    """Internal helper to shape a consistent response."""
    return {"status": "success", "message": message, "data": data}

# PUBLIC_INTERFACE
@router.get("/", tags=["Health"], summary="Health Check")
def health_check():
    """Health check endpoint indicating the API is up.

    Returns:
        JSON with status and a simple message.
    """
    return _ocean_response({"service": "integration_backend", "health": "healthy"}, "service healthy")

# PUBLIC_INTERFACE
@router.get(
    "/auth/jira",
    tags=["Auth"],
    summary="Get Jira OAuth authorization URL (JSON)",
    description="Returns JSON { url } with the Atlassian authorize URL constructed from environment configuration.",
)
async def auth_jira_json(state: Optional[str] = None, scope: Optional[str] = None):
    """App-level passthrough compatibility kept for reference; encourage using oauth_atlassian router."""
    from src.api import oauth_atlassian as oauth_router
    logging.getLogger("auth").info("Hit /auth/jira (api.main router); forwarding to router handler.")
    return await oauth_router.jira_get_oauth_url(state=state, scope=scope)

# PUBLIC_INTERFACE
@router.get(
    "/auth/jira/login",
    tags=["Auth"],
    summary="Start Jira OAuth 2.0 login",
    description="Redirects the user to Atlassian authorization page. Frontend should open this URL to start the flow.",
)
def jira_login(state: Optional[str] = None, scope: Optional[str] = None):
    """Initiate Jira OAuth 2.0 authorization flow using Atlassian OAuth 2.0 (3LO)."""
    cfg = get_jira_oauth_config()
    client_id = cfg.get("client_id")
    redirect_uri = cfg.get("redirect_uri")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Jira OAuth is not configured. Set environment variables.")

    default_scopes = [
        "read:jira-work",
        "read:jira-user",
        "offline_access",
    ]
    scopes = scope or " ".join(default_scopes)

    authorize_url = "https://auth.atlassian.com/authorize"
    params = {
        "audience": "api.atlassian.com",
        "client_id": client_id,
        "scope": scopes,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "prompt": "consent",
    }
    if state:
        params["state"] = state

    url = f"{authorize_url}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)

# PUBLIC_INTERFACE
@router.get(
    "/auth/jira/callback",
    tags=["Auth"],
    summary="Jira OAuth 2.0 callback",
    description="Handles Atlassian redirect, exchanges code for tokens, stores them on the first user (or targeted later), and redirects back to frontend.",
)
async def jira_callback(request: Request, db=Depends(get_db), code: Optional[str] = None, state: Optional[str] = None):
    """Complete Jira OAuth 2.0 flow and redirect back to frontend."""
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    cfg = get_jira_oauth_config()
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret")
    redirect_uri = cfg.get("redirect_uri")
    if not client_id or not client_secret or not redirect_uri:
        raise HTTPException(status_code=500, detail="Jira OAuth is not configured. Set environment variables.")

    token_url = "https://auth.atlassian.com/oauth/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        token_resp = await client.post(token_url, json=data, headers={"Content-Type": "application/json"})
        if token_resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Token exchange failed: {token_resp.text}")
        token_json = token_resp.json()

    access_token = token_json.get("access_token")
    refresh_token = token_json.get("refresh_token")
    expires_in = token_json.get("expires_in")  # seconds
    if not access_token:
        raise HTTPException(status_code=502, detail="No access token returned by Atlassian")

    users = list_users(db)
    if not users:
        raise HTTPException(status_code=400, detail="No user found. Create a user first via POST /users.")
    user = users[0]

    user.jira_token = access_token
    user.jira_refresh_token = refresh_token
    user.jira_expires_at = int(time.time()) + int(expires_in or 0)
    # store base URL if known from env
    from src.api.oauth_config import get_atlassian_base_url
    user.jira_base_url = get_atlassian_base_url() or user.jira_base_url
    db.commit()
    db.refresh(user)

    frontend = get_frontend_base_url_default() or "/"
    params = {
        "provider": "jira",
        "status": "success",
        "state": state or "",
        "user_id": str(user.id),
    }
    redirect_to = f"{frontend.rstrip('/')}/oauth/callback?{urllib.parse.urlencode(params)}"
    return RedirectResponse(redirect_to)

# PUBLIC_INTERFACE
@router.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    tags=["Users"],
    summary="Create user",
    description="Create a new user or return an existing one if the email already exists (idempotent).",
)
def create_user_endpoint(payload: UserCreate, db=Depends(get_db)):
    """Create or idempotently fetch a user."""
    user = create_user(
        db,
        email=payload.email,
        display_name=payload.display_name,
        jira_token=payload.jira_token,
        confluence_token=payload.confluence_token,
        jira_base_url=payload.jira_base_url,
        confluence_base_url=payload.confluence_base_url,
    )
    return user

# PUBLIC_INTERFACE
@router.get(
    "/users",
    response_model=List[UserRead],
    tags=["Users"],
    summary="List users",
    description="List all users.",
)
def list_users_endpoint(db=Depends(get_db)):
    """List all users."""
    return list_users(db)

# PUBLIC_INTERFACE
@router.get(
    "/users/{user_id}",
    response_model=UserRead,
    tags=["Users"],
    summary="Get user by ID",
    description="Retrieve a user by its internal ID.",
)
def get_user_endpoint(user_id: int, db=Depends(get_db)):
    """Get a single user by ID."""
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

# -----------------------
# Integrations - Fetch (placeholders) - Public
# -----------------------

# PUBLIC_INTERFACE
@router.get(
    "/integrations/jira/projects/fetch",
    tags=["Integrations", "JIRA Projects"],
    response_model=JiraProjectsFetchResponse,
    summary="Fetch JIRA projects (placeholder)",
    description="Fetches projects from JIRA for a user (demo: returns stored projects only). If none specified, uses the first user.",
)
def fetch_jira_projects(db=Depends(get_db), owner_id: int | None = None):
    """Return stored JIRA projects for the specified or first user."""
    resolved_owner_id = owner_id
    if resolved_owner_id is None:
        users = list_users(db)
        if not users:
            return JiraProjectsFetchResponse(provider="jira", items=[])
        resolved_owner_id = users[0].id
    projects = list_jira_projects_for_user(db, resolved_owner_id)
    return JiraProjectsFetchResponse(provider="jira", items=projects)

# PUBLIC_INTERFACE
@router.get(
    "/integrations/confluence/pages/fetch",
    tags=["Integrations", "Confluence Pages"],
    response_model=ConfluencePagesFetchResponse,
    summary="Fetch Confluence pages (placeholder)",
    description="Fetches pages from Confluence for a user (demo: returns stored pages only). If none specified, uses the first user.",
)
def fetch_confluence_pages(db=Depends(get_db), owner_id: int | None = None):
    """Return stored Confluence pages for the specified or first user."""
    resolved_owner_id = owner_id
    if resolved_owner_id is None:
        users = list_users(db)
        if not users:
            return ConfluencePagesFetchResponse(provider="confluence", items=[])
        resolved_owner_id = users[0].id
    pages = list_confluence_pages_for_user(db, resolved_owner_id)
    return ConfluencePagesFetchResponse(provider="confluence", items=pages)

# JIRA Projects (Public)
# PUBLIC_INTERFACE
@router.post(
    "/jira/projects",
    response_model=JiraProjectRead,
    status_code=status.HTTP_201_CREATED,
    tags=["JIRA Projects"],
    summary="Upsert JIRA project",
    description="Create or update a JIRA project for a given user keyed by (owner_id, key).",
)
def upsert_jira_project_endpoint(payload: JiraProjectCreate, db=Depends(get_db)):
    """Upsert a JIRA project tied to a user."""
    return upsert_jira_project(
        db,
        owner_id=payload.owner_id,
        key=payload.key,
        name=payload.name,
        lead=payload.lead,
        url=payload.url,
    )

# PUBLIC_INTERFACE
@router.get(
    "/jira/projects/{owner_id}",
    response_model=List[JiraProjectRead],
    tags=["JIRA Projects"],
    summary="List JIRA projects for user",
    description="List all JIRA projects owned by the given user.",
)
def list_jira_projects_endpoint(owner_id: int, db=Depends(get_db)):
    """List all stored JIRA projects for a specific owner."""
    return list_jira_projects_for_user(db, owner_id)

# Confluence Pages (Public)
# PUBLIC_INTERFACE
@router.post(
    "/confluence/pages",
    response_model=ConfluencePageRead,
    status_code=status.HTTP_201_CREATED,
    tags=["Confluence Pages"],
    summary="Upsert Confluence page",
    description="Create or update a Confluence page for a given user keyed by (owner_id, space_key, page_id).",
)
def upsert_confluence_page_endpoint(payload: ConfluencePageCreate, db=Depends(get_db)):
    """Upsert a Confluence page tied to a user."""
    return upsert_confluence_page(
        db,
        owner_id=payload.owner_id,
        space_key=payload.space_key,
        page_id=payload.page_id,
        title=payload.title,
        url=payload.url,
    )

# PUBLIC_INTERFACE
@router.get(
    "/confluence/pages/{owner_id}",
    response_model=List[ConfluencePageRead],
    tags=["Confluence Pages"],
    summary="List Confluence pages for user",
    description="List all Confluence pages owned by the given user.",
)
def list_confluence_pages_endpoint(owner_id: int, db=Depends(get_db)):
    """List all stored Confluence pages for a specific owner."""
    return list_confluence_pages_for_user(db, owner_id)
