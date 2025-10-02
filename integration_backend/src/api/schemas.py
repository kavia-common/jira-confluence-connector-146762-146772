"""
Pydantic models for API requests and responses.
"""

from __future__ import annotations

from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr


# PUBLIC_INTERFACE
class UserCreate(BaseModel):
    """Payload to create a user record (demo-only; tokens are optional)."""

    email: EmailStr = Field(..., description="User email (unique).")
    display_name: Optional[str] = Field(None, description="Display name.")
    jira_token: Optional[str] = Field(None, description="JIRA access token (demo).")
    confluence_token: Optional[str] = Field(None, description="Confluence access token (demo).")
    jira_base_url: Optional[str] = Field(None, description="Base URL for JIRA API.")
    confluence_base_url: Optional[str] = Field(None, description="Base URL for Confluence API.")


# PUBLIC_INTERFACE
class UserRead(BaseModel):
    """User response model (tokens omitted for safety)."""

    id: int
    email: EmailStr
    display_name: Optional[str]

    class Config:
        from_attributes = True


# PUBLIC_INTERFACE
class JiraProjectCreate(BaseModel):
    """Payload to create a JIRA project record for a user."""

    owner_id: int = Field(..., description="User ID who owns the project.")
    key: str = Field(..., description="JIRA Project key, e.g., 'ABC'.")
    name: str = Field(..., description="Project name.")
    lead: Optional[str] = Field(None, description="Project lead.")
    url: Optional[str] = Field(None, description="Deep link to project.")


# PUBLIC_INTERFACE
class JiraProjectRead(BaseModel):
    """Response model for JIRA projects."""

    id: int
    owner_id: int
    key: str
    name: str
    lead: Optional[str]
    url: Optional[str]

    class Config:
        from_attributes = True


# PUBLIC_INTERFACE
class ConfluencePageCreate(BaseModel):
    """Payload to create a Confluence page record for a user."""

    owner_id: int = Field(..., description="User ID who owns the page.")
    space_key: str = Field(..., description="Confluence space key, e.g., 'ENG'.")
    page_id: str = Field(..., description="Remote Confluence page ID.")
    title: str = Field(..., description="Page title.")
    url: Optional[str] = Field(None, description="Deep link to page.")


# PUBLIC_INTERFACE
class ConfluencePageRead(BaseModel):
    """Response model for Confluence pages."""

    id: int
    owner_id: int
    space_key: str
    page_id: str
    title: str
    url: Optional[str]

    class Config:
        from_attributes = True


# ---- Integration helper response schemas (auth removed) ----
# Note for frontend:
# - To start OAuth, open GET /auth/jira/login (or /auth/confluence/login).
# - Atlassian will redirect to our /auth/.../callback which will persist tokens server-side.
# - On success we redirect to APP_FRONTEND_URL + /oauth/callback?provider=...&status=success&user_id=...
#   Your frontend should handle this route and update UI state accordingly (e.g., "Connected").

# PUBLIC_INTERFACE
class ConnectResponse(BaseModel):
    """Response confirming connection settings were saved."""

    provider: str = Field(..., description="Provider name, e.g., 'jira' or 'confluence'.")
    base_url: str = Field(..., description="Saved base URL.")
    connected: bool = Field(..., description="Whether settings were saved successfully.")
    redirect_url: Optional[str] = Field(
        None,
        description="Optional URL to which the frontend should redirect after successful verification.",
    )


# PUBLIC_INTERFACE
class JiraProjectsFetchResponse(BaseModel):
    """Response wrapper for fetched JIRA projects (placeholder from persistence)."""

    provider: str = Field(..., description="Provider name, always 'jira' here.")
    items: List[JiraProjectRead] = Field(..., description="List of stored projects.")


# PUBLIC_INTERFACE
class ConfluencePagesFetchResponse(BaseModel):
    """Response wrapper for fetched Confluence pages (placeholder from persistence)."""

    provider: str = Field(..., description="Provider name, always 'confluence' here.")
    items: List[ConfluencePageRead] = Field(..., description="List of stored pages.")
