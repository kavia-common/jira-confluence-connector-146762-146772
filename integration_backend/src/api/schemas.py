from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

# PUBLIC_INTERFACE
class SearchResultItem(BaseModel):
    """Normalized search result item across providers."""
    id: str = Field(..., description="Provider-specific unique id or key")
    title: str = Field(..., description="Display title")
    url: str = Field(..., description="Deep link URL")
    type: str = Field(..., description="Resource type, e.g., 'issue', 'page'")
    icon: Optional[str] = Field(None, description="Optional icon URL")
    snippet: Optional[str] = Field(None, description="Optional short description/snippet")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata")


# PUBLIC_INTERFACE
class CreateResult(BaseModel):
    """Normalized create result returned by create operations."""
    id: str = Field(..., description="Created resource id/key")
    url: Optional[str] = Field(None, description="Deep link to newly created resource")
    title: Optional[str] = Field(None, description="Title of the created resource")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


# PUBLIC_INTERFACE
class ConnectionStatus(BaseModel):
    """Connection status for a tenant."""
    connected: bool = Field(..., description="Whether the tenant is connected")
    scopes: Optional[List[str]] = Field(None, description="Granted scopes, if known")
    expires_at: Optional[int] = Field(None, description="Epoch seconds when the access token expires")
    refreshed_at: Optional[int] = Field(None, description="Epoch seconds when the token was last refreshed")
    error: Optional[str] = Field(None, description="Last error, if any")


# PUBLIC_INTERFACE
class OAuthAuthorizeURL(BaseModel):
    """Response model containing an OAuth authorize URL."""
    url: str = Field(..., description="Full Atlassian OAuth authorize URL to navigate to.")


# PUBLIC_INTERFACE
class SessionResponse(BaseModel):
    """Session check response."""
    authenticated: bool = Field(..., description="Whether the request has a valid session")
    user: Optional[Dict[str, Any]] = Field(None, description="User info when authenticated")


# PUBLIC_INTERFACE
class LoginRequest(BaseModel):
    """Credential login payload."""
    email: Optional[str] = Field(None, description="User email")
    username: Optional[str] = Field(None, description="Username")
    password: str = Field(..., description="Password")


# PUBLIC_INTERFACE
class TokenResponse(BaseModel):
    """Token response shape."""
    access_token: str = Field(..., description="Access token")
    refresh_token: str = Field(..., description="Refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Access token expiry in seconds")


# PUBLIC_INTERFACE
class UserCreate(BaseModel):
    """Payload to create a user record (demo-only; tokens are optional)."""
    email: str = Field(..., description="User email (unique).")
    display_name: Optional[str] = Field(None, description="Display name.")
    jira_token: Optional[str] = Field(None, description="JIRA access token (demo).")
    confluence_token: Optional[str] = Field(None, description="Confluence access token (demo).")
    jira_base_url: Optional[str] = Field(None, description="Base URL for JIRA API.")
    confluence_base_url: Optional[str] = Field(None, description="Base URL for Confluence API.")


# PUBLIC_INTERFACE
class UserRead(BaseModel):
    """User response model (tokens omitted for safety)."""
    id: int = Field(..., description="User id")
    email: str = Field(..., description="User email")
    display_name: Optional[str] = Field(None, description="Display name")


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
    id: int = Field(..., description="Id")
    owner_id: int = Field(..., description="Owner Id")
    key: str = Field(..., description="Key")
    name: str = Field(..., description="Name")
    lead: Optional[str] = Field(None, description="Lead")
    url: Optional[str] = Field(None, description="Url")


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
    id: int = Field(..., description="Id")
    owner_id: int = Field(..., description="Owner Id")
    space_key: str = Field(..., description="Space Key")
    page_id: str = Field(..., description="Page Id")
    title: str = Field(..., description="Title")
    url: Optional[str] = Field(None, description="Url")


# PUBLIC_INTERFACE
class JiraProjectsFetchResponse(BaseModel):
    """Response wrapper for fetched JIRA projects (placeholder from persistence)."""
    provider: str = Field(..., description="Provider name, always 'jira' here.")
    items: List[JiraProjectRead] = Field(default_factory=list, description="List of stored projects.")


# PUBLIC_INTERFACE
class ConfluencePagesFetchResponse(BaseModel):
    """Response wrapper for fetched Confluence pages (placeholder from persistence)."""
    provider: str = Field(..., description="Provider name, always 'confluence' here.")
    items: List[ConfluencePageRead] = Field(default_factory=list, description="List of stored pages.")
