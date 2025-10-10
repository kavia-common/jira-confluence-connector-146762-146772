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
