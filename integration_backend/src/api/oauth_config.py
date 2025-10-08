"""
OAuth configuration helper for Atlassian (JIRA/Confluence) OAuth 2.0 (3LO) flows.

All configuration is pulled from environment variables. Do NOT hardcode sensitive data.
Required environment variables (example .env is provided separately):

- ATLASSIAN_CLOUD_BASE_URL: The base URL of your Atlassian Cloud site, e.g. "https://your-team.atlassian.net"
- JIRA_OAUTH_CLIENT_ID: OAuth client ID for your Jira/Atlassian app
- JIRA_OAUTH_CLIENT_SECRET: OAuth client secret for your Jira/Atlassian app
- JIRA_OAUTH_REDIRECT_URI: Redirect URI configured in Atlassian developer console, e.g. "https://yourapp.com/api/auth/jira/callback"

- CONFLUENCE_OAUTH_CLIENT_ID, CONFLUENCE_OAUTH_CLIENT_SECRET, CONFLUENCE_OAUTH_REDIRECT_URI:
  If you use a distinct app/client for Confluence. If not set, Jira values will be reused.

- APP_FRONTEND_URL: Frontend base URL to return the user to after auth success/failure (used for guiding the frontend). Optional.

Note:
- Scopes must be configured on Atlassian side. During authorization, pass the scopes needed by your app.
"""
from __future__ import annotations

import os
import urllib.parse
from typing import Dict, Optional
from pydantic import BaseModel, Field


def _env_first(*names: str) -> str:
    """Return the first non-empty environment variable value among names (trimmed)."""
    for name in names:
        val = os.getenv(name, "")
        if val and val.strip():
            return val.strip()
    return ""


class Settings(BaseModel):
    """
    Central runtime settings loaded from environment.
    Uses simple os.getenv lookups to avoid adding heavy dependencies.
    """

    app_env: str = Field(default=os.getenv("APP_ENV", os.getenv("ENV", "production")))
    dev_mode: bool = Field(default=os.getenv("DEV_MODE", "false").lower() in ("1", "true", "yes"))
    log_level: str = Field(default=os.getenv("LOG_LEVEL", "INFO"))
    # CORS
    backend_cors_origins: str = Field(default=os.getenv("BACKEND_CORS_ORIGINS", os.getenv("NEXT_PUBLIC_BACKEND_CORS_ORIGINS", "*")))
    frontend_url: Optional[str] = Field(default=_env_first("APP_FRONTEND_URL", "NEXT_PUBLIC_APP_FRONTEND_URL", "NEXT_PUBLIC_FRONTEND_BASE_URL"))

    # Atlassian base
    atlassian_base_url: Optional[str] = Field(default=_env_first("ATLASSIAN_CLOUD_BASE_URL", "NEXT_PUBLIC_ATLASSIAN_CLOUD_BASE_URL"))

    # Jira OAuth
    jira_client_id: Optional[str] = Field(default=_env_first("JIRA_OAUTH_CLIENT_ID", "ATLASSIAN_CLIENT_ID", "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID", "NEXT_PUBLIC_JIRA_CLIENT_ID", "NEXT_PUBLIC_ATLASSIAN_CLIENT_ID"))
    jira_client_secret: Optional[str] = Field(default=_env_first("JIRA_OAUTH_CLIENT_SECRET", "ATLASSIAN_CLIENT_SECRET", "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET", "NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET"))
    jira_redirect_uri: Optional[str] = Field(default=_env_first("JIRA_OAUTH_REDIRECT_URI", "ATLASSIAN_REDIRECT_URI", "NEXT_PUBLIC_JIRA_OAUTH_REDIRECT_URI", "NEXT_PUBLIC_ATLASSIAN_REDIRECT_URI"))

    # Confluence OAuth
    confluence_client_id: Optional[str] = Field(default=_env_first("CONFLUENCE_OAUTH_CLIENT_ID", "JIRA_OAUTH_CLIENT_ID", "ATLASSIAN_CLIENT_ID", "NEXT_PUBLIC_CONFLUENCE_OAUTH_CLIENT_ID", "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID", "NEXT_PUBLIC_JIRA_CLIENT_ID", "NEXT_PUBLIC_ATLASSIAN_CLIENT_ID"))
    confluence_client_secret: Optional[str] = Field(default=_env_first("CONFLUENCE_OAUTH_CLIENT_SECRET", "JIRA_OAUTH_CLIENT_SECRET", "ATLASSIAN_CLIENT_SECRET", "NEXT_PUBLIC_CONFLUENCE_OAUTH_CLIENT_SECRET", "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET", "NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET"))
    confluence_redirect_uri: Optional[str] = Field(default=_env_first("CONFLUENCE_OAUTH_REDIRECT_URI", "JIRA_OAUTH_REDIRECT_URI", "ATLASSIAN_REDIRECT_URI", "NEXT_PUBLIC_CONFLUENCE_OAUTH_REDIRECT_URI", "NEXT_PUBLIC_JIRA_OAUTH_REDIRECT_URI", "NEXT_PUBLIC_ATLASSIAN_REDIRECT_URI"))


# Load settings once at startup. To pick up new envs, restart the server process.
_SETTINGS = Settings()


def _is_truthy(val: Optional[str | bool]) -> bool:
    """Utility to parse typical truthy env flag values."""
    if isinstance(val, bool):
        return val
    if not val:
        return False
    return str(val).strip().lower() in ("1", "true", "yes", "on")


# PUBLIC_INTERFACE
def get_atlassian_base_url() -> str:
    """Return Atlassian Cloud base URL (e.g., https://your-team.atlassian.net)."""
    return (_SETTINGS.atlassian_base_url or "").strip()


# PUBLIC_INTERFACE
def get_jira_oauth_config() -> Dict[str, str]:
    """Return Jira OAuth 2.0 config from the environment with robust fallbacks."""
    return {
        "client_id": (_SETTINGS.jira_client_id or "").strip(),
        "client_secret": (_SETTINGS.jira_client_secret or "").strip(),
        "redirect_uri": (_SETTINGS.jira_redirect_uri or "").strip(),
        "base_url": get_atlassian_base_url(),
        "dev_mode": str(_SETTINGS.dev_mode).lower(),
        "app_env": (_SETTINGS.app_env or "production").strip(),
        "frontend_url": (_SETTINGS.frontend_url or "").strip(),
    }


# PUBLIC_INTERFACE
def get_confluence_oauth_config() -> Dict[str, str]:
    """
    Return Confluence OAuth 2.0 config from the environment.
    Falls back to Jira or generic Atlassian config if dedicated Confluence values are not provided.
    """
    return {
        "client_id": (_SETTINGS.confluence_client_id or "").strip(),
        "client_secret": (_SETTINGS.confluence_client_secret or "").strip(),
        "redirect_uri": (_SETTINGS.confluence_redirect_uri or "").strip(),
        "base_url": get_atlassian_base_url(),
        "dev_mode": str(_SETTINGS.dev_mode).lower(),
        "app_env": (_SETTINGS.app_env or "production").strip(),
        "frontend_url": (_SETTINGS.frontend_url or "").strip(),
    }


# PUBLIC_INTERFACE
def get_frontend_base_url_default() -> str:
    """Return frontend base URL to guide redirects after auth."""
    return (_SETTINGS.frontend_url or "").strip()


# PUBLIC_INTERFACE
def is_jira_oauth_configured() -> bool:
    """Quick boolean check to determine if Jira OAuth has required fields."""
    cfg = get_jira_oauth_config()
    return bool(cfg.get("client_id")) and bool(cfg.get("redirect_uri"))


# PUBLIC_INTERFACE
def build_atlassian_authorize_url(client_id: str, redirect_uri: str, scopes: str, state: Optional[str] = None) -> str:
    """
    Build the Atlassian OAuth2 authorize URL for the given parameters.
    """
    base = "https://auth.atlassian.com/authorize"
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
    return f"{base}?{urllib.parse.urlencode(params)}"
