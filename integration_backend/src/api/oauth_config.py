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
from typing import Dict


# PUBLIC_INTERFACE
def get_atlassian_base_url() -> str:
    """Return Atlassian Cloud base URL (e.g., https://your-team.atlassian.net)."""
    return os.getenv("ATLASSIAN_CLOUD_BASE_URL", "").strip()


# PUBLIC_INTERFACE
def get_jira_oauth_config() -> Dict[str, str]:
    """Return Jira OAuth 2.0 config from the environment."""
    return {
        "client_id": os.getenv("JIRA_OAUTH_CLIENT_ID", "").strip(),
        "client_secret": os.getenv("JIRA_OAUTH_CLIENT_SECRET", "").strip(),
        "redirect_uri": os.getenv("JIRA_OAUTH_REDIRECT_URI", "").strip(),
        "base_url": get_atlassian_base_url(),
    }


# PUBLIC_INTERFACE
def get_confluence_oauth_config() -> Dict[str, str]:
    """
    Return Confluence OAuth 2.0 config from the environment.
    Falls back to Jira config if dedicated Confluence values are not provided.
    """
    jira_cfg = get_jira_oauth_config()
    return {
        "client_id": os.getenv("CONFLUENCE_OAUTH_CLIENT_ID", jira_cfg["client_id"]).strip(),
        "client_secret": os.getenv("CONFLUENCE_OAUTH_CLIENT_SECRET", jira_cfg["client_secret"]).strip(),
        "redirect_uri": os.getenv("CONFLUENCE_OAUTH_REDIRECT_URI", jira_cfg["redirect_uri"]).strip(),
        "base_url": get_atlassian_base_url(),
    }


# PUBLIC_INTERFACE
def get_frontend_base_url_default() -> str:
    """Return frontend base URL to guide redirects after auth."""
    return os.getenv("FRONTEND_BASE_URL", "").strip()
