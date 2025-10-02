from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any

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
]

app = FastAPI(
    title="Jira-Confluence Integration API",
    description="Backend API for integrating JIRA and Confluence, with a lightweight persistence layer.",
    version="0.1.0",
    openapi_tags=openapi_tags,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
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

# PUBLIC_INTERFACE
@app.post(
    "/integrations/jira/connect",
    tags=["Integrations"],
    response_model=ConnectResponse,
    summary="Connect JIRA (auto, no user input)",
    description="Automatically uses hard-coded credentials to connect to JIRA and store on the target user.",
)
def connect_jira(db=Depends(get_db), payload: UserCreate | None = None):
    """
    Store JIRA connection details using hard-coded credentials (demo-only).
    If a user exists for the provided email, it will be used; otherwise a user can be created first via /users.

    Returns:
        ConnectResponse summary of saved settings including optional redirect_url.
    """
    # Lazy import to avoid circulars and keep dependency surface small
    from src.api.integrations_config import get_jira_credentials

    creds = get_jira_credentials()
    base_url = creds["base_url"]
    access_token = creds["access_token"]

    if not base_url or not access_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="JIRA credentials are not configured")

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

    target_user.jira_base_url = base_url
    target_user.jira_token = access_token
    db.commit()
    db.refresh(target_user)

    redirect = f"{base_url}/jira/your-work" if base_url else None
    return ConnectResponse(provider="jira", base_url=target_user.jira_base_url, connected=True, redirect_url=redirect)


# PUBLIC_INTERFACE
@app.post(
    "/integrations/confluence/connect",
    tags=["Integrations"],
    response_model=ConnectResponse,
    summary="Connect Confluence (auto, no user input)",
    description="Automatically uses hard-coded credentials to connect to Confluence and store on the target user.",
)
def connect_confluence(db=Depends(get_db), payload: UserCreate | None = None):
    """
    Store Confluence connection details using hard-coded credentials (demo-only).
    If a user exists for the provided email, it will be used; otherwise a user can be created first via /users.

    Returns:
        ConnectResponse summary of saved settings including optional redirect_url.
    """
    from src.api.integrations_config import get_confluence_credentials

    creds = get_confluence_credentials()
    base_url = creds["base_url"]
    access_token = creds["access_token"]

    if not base_url or not access_token:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Confluence credentials are not configured")

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
    target_user.confluence_token = access_token
    db.commit()
    db.refresh(target_user)

    redirect = f"{base_url}/spaces/viewspacesummary.action" if base_url else None
    return ConnectResponse(provider="confluence", base_url=target_user.confluence_base_url, connected=True, redirect_url=redirect)


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
