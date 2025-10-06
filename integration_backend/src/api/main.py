from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from typing import List, Dict, Any, Optional
import time
import urllib.parse
import httpx

from src.db.config import Base, engine, get_db

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
    get_confluence_oauth_config,
    get_frontend_base_url_default,
)
from src.api.schemas import (
    UserCreate,
    UserRead,
    JiraProjectCreate,
    JiraProjectRead,
    ConfluencePageCreate,
    ConfluencePageRead,
    ConnectResponse,
    JiraProjectsFetchResponse,
    ConfluencePagesFetchResponse,
)

openapi_tags = [
    {"name": "Health", "description": "Health and readiness checks."},
    {"name": "Users", "description": "Manage users who connect JIRA/Confluence."},
    {"name": "JIRA Projects", "description": "Manage synced JIRA projects."},
    {"name": "Confluence Pages", "description": "Manage synced Confluence pages."},
    {"name": "Integrations", "description": "Connect and fetch from JIRA/Confluence (placeholders)."},
    {"name": "Auth", "description": "OAuth 2.0 authorization flows for Atlassian (Jira/Confluence)."},
]

app = FastAPI(
    title="Jira-Confluence Integration API",
    description="Backend API for integrating JIRA and Confluence, with a lightweight persistence layer.",
    version="0.1.0",
    openapi_tags=openapi_tags,
)

# CORS: explicitly allow the preview frontend origin in addition to existing settings.
frontend_preview_origin = "https://vscode-internal-36910-beta.beta01.cloud.kavia.ai:4000"
allowed_origins = ["*"]
if "*" not in allowed_origins and frontend_preview_origin not in allowed_origins:
    allowed_origins.append(frontend_preview_origin)

# For simple GET /auth/jira JSON usage, credentials are not required.
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS", "POST"],
    allow_headers=["*"],
)

# Initialize database tables (for demo; in production, prefer migrations)
Base.metadata.create_all(bind=engine)


def _ocean_response(data: Any, message: str = "ok") -> Dict[str, Any]:
    """
    Wrap responses using a simple 'Ocean Professional' style envelope.

    This keeps API responses consistent across endpoints.
    """
    return {"status": "success", "message": message, "data": data}


# PUBLIC_INTERFACE
@app.get("/", tags=["Health"], summary="Health Check")
def health_check():
    """
    Health check endpoint indicating the API is up.

    Returns:
        JSON with status and a simple message.
    """
    return _ocean_response({"service": "integration_backend", "health": "healthy"}, "service healthy")


# Users (Public)

# -----------------------
# OAuth 2.0 for Atlassian - Jira
# -----------------------

# PUBLIC_INTERFACE
@app.get(
    "/auth/jira/login",
    tags=["Auth"],
    summary="Start Jira OAuth 2.0 login",
    description="Redirects the user to Atlassian authorization page. Frontend should open this URL to start the flow.",
)
def jira_login(state: Optional[str] = None, scope: Optional[str] = None):
    """
    Initiate Jira OAuth 2.0 authorization flow using Atlassian OAuth 2.0 (3LO).
    Parameters:
        state: Optional opaque state to be returned by Atlassian to mitigate CSRF (frontend should generate and verify).
        scope: Optional space-separated scopes. If not provided, defaults to commonly used scopes configured in your app.
    Returns:
        Redirect to Atlassian authorization endpoint.
    """
    cfg = get_jira_oauth_config()
    client_id = cfg.get("client_id")
    redirect_uri = cfg.get("redirect_uri")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Jira OAuth is not configured. Set environment variables.")

    # Default scopes can be tailored based on your app setup in Atlassian developer console
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
@app.get(
    "/auth/jira/callback",
    tags=["Auth"],
    summary="Jira OAuth 2.0 callback",
    description="Handles Atlassian redirect, exchanges code for tokens, stores them on the first user (or targeted later), and redirects back to frontend.",
)
async def jira_callback(request: Request, db=Depends(get_db), code: Optional[str] = None, state: Optional[str] = None):
    """
    Complete Jira OAuth 2.0 flow:
    - Exchange authorization code for access and refresh tokens
    - Store tokens and expiry on a user (demo: first user)
    - Redirect to frontend with status
    """
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

    # For demo simplicity: store on the first user (or require selecting target later)
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

    # Redirect back to frontend
    frontend = get_frontend_base_url_default() or "/"
    # Include minimal status info; avoid exposing tokens
    params = {
        "provider": "jira",
        "status": "success",
        "state": state or "",
        "user_id": str(user.id),
    }
    redirect_to = f"{frontend.rstrip('/')}/oauth/callback?{urllib.parse.urlencode(params)}"
    return RedirectResponse(redirect_to)
# PUBLIC_INTERFACE
@app.post(
    "/users",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    tags=["Users"],
    summary="Create user",
    description="Create a new user or return an existing one if the email already exists (idempotent).",
)
def create_user_endpoint(payload: UserCreate, db=Depends(get_db)):
    """
    Create or idempotently fetch a user.

    Parameters:
        payload: UserCreate - includes optional placeholder tokens for JIRA and Confluence
    Returns:
        UserRead
    """
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
@app.get(
    "/users",
    response_model=List[UserRead],
    tags=["Users"],
    summary="List users",
    description="List all users.",
)
def list_users_endpoint(db=Depends(get_db)):
    """
    List all users.

    Note:
        This endpoint is public and does not require authentication.
    """
    return list_users(db)


# PUBLIC_INTERFACE
@app.get(
    "/users/{user_id}",
    response_model=UserRead,
    tags=["Users"],
    summary="Get user by ID",
    description="Retrieve a user by its internal ID.",
)
def get_user_endpoint(user_id: int, db=Depends(get_db)):
    """
    Get a single user by ID.

    Raises:
        404 if user not found.
    """
    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# -----------------------
# Integrations - Connect (Public demo flows)

# -----------------------
# OAuth 2.0 for Atlassian - Confluence
# -----------------------

# PUBLIC_INTERFACE
@app.get(
    "/auth/confluence/login",
    tags=["Auth"],
    summary="Start Confluence OAuth 2.0 login",
    description="Redirects the user to Atlassian authorization page for Confluence scopes.",
)
def confluence_login(state: Optional[str] = None, scope: Optional[str] = None):
    """
    Initiate Confluence OAuth 2.0 authorization flow.
    """
    cfg = get_confluence_oauth_config()
    client_id = cfg.get("client_id")
    redirect_uri = cfg.get("redirect_uri")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Confluence OAuth is not configured. Set environment variables.")

    default_scopes = [
        "read:confluence-content.all",
        "read:confluence-space.summary",
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
@app.get(
    "/auth/confluence/callback",
    tags=["Auth"],
    summary="Confluence OAuth 2.0 callback",
    description="Handles Atlassian redirect, exchanges code for tokens, stores them on the first user, and redirects back to frontend.",
)
async def confluence_callback(request: Request, db=Depends(get_db), code: Optional[str] = None, state: Optional[str] = None):
    """
    Complete Confluence OAuth 2.0 flow (token exchange and persistence).
    """
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    cfg = get_confluence_oauth_config()
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret")
    redirect_uri = cfg.get("redirect_uri")
    if not client_id or not client_secret or not redirect_uri:
        raise HTTPException(status_code=500, detail="Confluence OAuth is not configured. Set environment variables.")

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
    expires_in = token_json.get("expires_in")
    if not access_token:
        raise HTTPException(status_code=502, detail="No access token returned by Atlassian")

    users = list_users(db)
    if not users:
        raise HTTPException(status_code=400, detail="No user found. Create a user first via POST /users.")
    user = users[0]

    user.confluence_token = access_token
    user.confluence_refresh_token = refresh_token
    user.confluence_expires_at = int(time.time()) + int(expires_in or 0)
    from src.api.oauth_config import get_atlassian_base_url
    # Commonly the wiki lives under <base>/wiki
    base = get_atlassian_base_url()
    user.confluence_base_url = (base.rstrip("/") + "/wiki") if base else user.confluence_base_url
    db.commit()
    db.refresh(user)

    frontend = get_frontend_base_url_default() or "/"
    params = {
        "provider": "confluence",
        "status": "success",
        "state": state or "",
        "user_id": str(user.id),
    }
    redirect_to = f"{frontend.rstrip('/')}/oauth/callback?{urllib.parse.urlencode(params)}"
    return RedirectResponse(redirect_to)
# -----------------------

# PUBLIC_INTERFACE
@app.post(
    "/integrations/jira/connect",
    tags=["Integrations"],
    response_model=ConnectResponse,
    summary="Connect JIRA (auto, no user input)",
    description="Use OAuth 2.0 flow for JIRA. This endpoint now returns guidance to start /auth/jira/login.",
)
def connect_jira(db=Depends(get_db), payload: UserCreate | None = None):
    """
    Store JIRA connection details using hard-coded credentials (demo-only).
    If a user exists for the provided email, it will be used; otherwise a user can be created first via /users.

    Returns:
        ConnectResponse summary of saved settings including optional redirect_url.
    """
    # Lazy import to avoid circulars and keep dependency surface small
    # Removed legacy import of hardcoded credentials; OAuth flow is used instead.

    # This demo endpoint no longer persists tokens directly. It guides the client to start OAuth.
    from src.api.oauth_config import get_atlassian_base_url
    base_url = get_atlassian_base_url()
    if not base_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Atlassian base URL is not configured")

    # For demo simplicity, if payload with email is provided, upsert/get that user; else use first user if any.
    target_user = None
    if payload and payload.email:
        target_user = create_user(
            db,
            email=payload.email,
            display_name=payload.display_name,
            jira_token=payload.jira_token,
            confluence_token=payload.confluence_token,
            jira_base_url=payload.jira_base_url,
            confluence_base_url=payload.confluence_base_url,
        )
    else:
        users = list_users(db)
        target_user = users[0] if users else None

    if not target_user:
        raise HTTPException(
            status_code=400,
            detail="No user available. Create a user first via POST /users (provide an email).",
        )

    # Keep/update user's base_url only; do not set token here.
    target_user.jira_base_url = base_url
    db.commit()
    db.refresh(target_user)

    redirect = "/auth/jira/login"  # frontend should navigate here to start OAuth
    return ConnectResponse(provider="jira", base_url=target_user.jira_base_url or "", connected=True, redirect_url=redirect)


# PUBLIC_INTERFACE
@app.post(
    "/integrations/confluence/connect",
    tags=["Integrations"],
    response_model=ConnectResponse,
    summary="Connect Confluence (auto, no user input)",
    description="Use OAuth 2.0 flow for Confluence. This endpoint now returns guidance to start /auth/confluence/login.",
)
def connect_confluence(db=Depends(get_db), payload: UserCreate | None = None):
    """
    Store Confluence connection details using hard-coded credentials (demo-only).
    If a user exists for the provided email, it will be used; otherwise a user can be created first via /users.

    Returns:
        ConnectResponse summary of saved settings including optional redirect_url.
    """
    # Removed legacy import of hardcoded credentials; OAuth flow is used instead.

    from src.api.oauth_config import get_atlassian_base_url
    base_core = get_atlassian_base_url()
    base_url = (base_core.rstrip("/") + "/wiki") if base_core else None

    if not base_url:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Atlassian base URL is not configured")

    target_user = None
    if payload and payload.email:
        target_user = create_user(
            db,
            email=payload.email,
            display_name=payload.display_name,
            jira_token=payload.jira_token,
            confluence_token=payload.confluence_token,
            jira_base_url=payload.jira_base_url,
            confluence_base_url=payload.confluence_base_url,
        )
    else:
        users = list_users(db)
        target_user = users[0] if users else None

    if not target_user:
        raise HTTPException(
            status_code=400,
            detail="No user available. Create a user first via POST /users (provide an email).",
        )

    target_user.confluence_base_url = base_url
    db.commit()
    db.refresh(target_user)

    redirect = "/auth/confluence/login"
    return ConnectResponse(provider="confluence", base_url=target_user.confluence_base_url or "", connected=True, redirect_url=redirect)


# -----------------------
# Integrations - Fetch (placeholders) - Public
# -----------------------

# PUBLIC_INTERFACE
@app.get(
    "/integrations/jira/projects/fetch",
    tags=["Integrations", "JIRA Projects"],
    response_model=JiraProjectsFetchResponse,
    summary="Fetch JIRA projects (placeholder)",
    description="Fetches projects from JIRA for a user (demo: returns stored projects only). If none specified, uses the first user.",
)
def fetch_jira_projects(db=Depends(get_db), owner_id: int | None = None):
    """
    Placeholder fetch: uses stored base URL and token to query JIRA (omitted), and returns what's stored.
    If owner_id is not provided, the first user (if any) is used.
    """
    resolved_owner_id = owner_id
    if resolved_owner_id is None:
        users = list_users(db)
        if not users:
            return JiraProjectsFetchResponse(provider="jira", items=[])
        resolved_owner_id = users[0].id
    projects = list_jira_projects_for_user(db, resolved_owner_id)
    return JiraProjectsFetchResponse(provider="jira", items=projects)


# PUBLIC_INTERFACE
@app.get(
    "/integrations/confluence/pages/fetch",
    tags=["Integrations", "Confluence Pages"],
    response_model=ConfluencePagesFetchResponse,
    summary="Fetch Confluence pages (placeholder)",
    description="Fetches pages from Confluence for a user (demo: returns stored pages only). If none specified, uses the first user.",
)
def fetch_confluence_pages(db=Depends(get_db), owner_id: int | None = None):
    """
    Placeholder fetch: uses stored base URL and token to query Confluence (omitted), and returns what's stored.
    If owner_id is not provided, the first user (if any) is used.
    """
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
@app.post(
    "/jira/projects",
    response_model=JiraProjectRead,
    status_code=status.HTTP_201_CREATED,
    tags=["JIRA Projects"],
    summary="Upsert JIRA project",
    description="Create or update a JIRA project for a given user keyed by (owner_id, key).",
)
def upsert_jira_project_endpoint(payload: JiraProjectCreate, db=Depends(get_db)):
    """
    Upsert a JIRA project tied to a user.
    """
    return upsert_jira_project(
        db,
        owner_id=payload.owner_id,
        key=payload.key,
        name=payload.name,
        lead=payload.lead,
        url=payload.url,
    )


# PUBLIC_INTERFACE
@app.get(
    "/jira/projects/{owner_id}",
    response_model=List[JiraProjectRead],
    tags=["JIRA Projects"],
    summary="List JIRA projects for user",
    description="List all JIRA projects owned by the given user.",
)
def list_jira_projects_endpoint(owner_id: int, db=Depends(get_db)):
    """
    List all stored JIRA projects for a specific owner.
    """
    return list_jira_projects_for_user(db, owner_id)


# Confluence Pages (Public)
# PUBLIC_INTERFACE
@app.post(
    "/confluence/pages",
    response_model=ConfluencePageRead,
    status_code=status.HTTP_201_CREATED,
    tags=["Confluence Pages"],
    summary="Upsert Confluence page",
    description="Create or update a Confluence page for a given user keyed by (owner_id, space_key, page_id).",
)
def upsert_confluence_page_endpoint(payload: ConfluencePageCreate, db=Depends(get_db)):
    """
    Upsert a Confluence page tied to a user.
    """
    return upsert_confluence_page(
        db,
        owner_id=payload.owner_id,
        space_key=payload.space_key,
        page_id=payload.page_id,
        title=payload.title,
        url=payload.url,
    )


# PUBLIC_INTERFACE
@app.get(
    "/confluence/pages/{owner_id}",
    response_model=List[ConfluencePageRead],
    tags=["Confluence Pages"],
    summary="List Confluence pages for user",
    description="List all Confluence pages owned by the given user.",
)
def list_confluence_pages_endpoint(owner_id: int, db=Depends(get_db)):
    """
    List all stored Confluence pages for a specific owner.
    """
    return list_confluence_pages_for_user(db, owner_id)
