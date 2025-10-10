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


def _env_first(*names: str, default: str = "") -> str:
    """Return the first non-empty environment variable value among names (trimmed)."""
    for name in names:
        val = os.getenv(name, "")
        if val and val.strip():
            return val.strip()
    return default


# PUBLIC_INTERFACE
def get_atlassian_base_url() -> str:
    """Return Atlassian Cloud base URL (e.g., https://your-team.atlassian.net)."""
    return _env_first(
        "ATLASSIAN_CLOUD_BASE_URL",
        "NEXT_PUBLIC_ATLASSIAN_CLOUD_BASE_URL",
    )


# PUBLIC_INTERFACE
def get_jira_oauth_config() -> Dict[str, str]:
    """Return Jira OAuth 2.0 config from the environment with robust fallbacks.

    Redirect URI resolution prefers explicit JIRA_REDIRECT_URI style variables and
    falls back to the provided default callback URL if nothing is set.
    """
    client_id = _env_first(
        "JIRA_OAUTH_CLIENT_ID",
        "ATLASSIAN_CLIENT_ID",
        "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID",
        "NEXT_PUBLIC_JIRA_CLIENT_ID",
        "NEXT_PUBLIC_ATLASSIAN_CLIENT_ID",
    )
    client_secret = _env_first(
        "JIRA_OAUTH_CLIENT_SECRET",
        "ATLASSIAN_CLIENT_SECRET",
        "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET",
        "NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET",
    )
    # Resolve redirect URI with strong precedence and a safe default
    default_redirect = "https://vscode-internal-37302-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback"
    redirect_uri = _env_first(
        # new canonical env
        "JIRA_REDIRECT_URI",
        # existing variants
        "JIRA_OAUTH_REDIRECT_URI",
        "ATLASSIAN_REDIRECT_URI",
        "NEXT_PUBLIC_JIRA_REDIRECT_URI",
        "NEXT_PUBLIC_JIRA_OAUTH_REDIRECT_URI",
        "NEXT_PUBLIC_ATLASSIAN_REDIRECT_URI",
        default=default_redirect,
    )
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "base_url": get_atlassian_base_url(),
    }


# PUBLIC_INTERFACE
def get_confluence_oauth_config() -> Dict[str, str]:
    """
    Return Confluence OAuth 2.0 config from the environment.
    Falls back to Jira or generic Atlassian config if dedicated Confluence values are not provided.
    """
    client_id = _env_first(
        "CONFLUENCE_OAUTH_CLIENT_ID",
        "JIRA_OAUTH_CLIENT_ID",
        "ATLASSIAN_CLIENT_ID",
        "NEXT_PUBLIC_CONFLUENCE_OAUTH_CLIENT_ID",
        "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID",
        "NEXT_PUBLIC_JIRA_CLIENT_ID",
        "NEXT_PUBLIC_ATLASSIAN_CLIENT_ID",
    )
    client_secret = _env_first(
        "CONFLUENCE_OAUTH_CLIENT_SECRET",
        "JIRA_OAUTH_CLIENT_SECRET",
        "ATLASSIAN_CLIENT_SECRET",
        "NEXT_PUBLIC_CONFLUENCE_OAUTH_CLIENT_SECRET",
        "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET",
        "NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET",
    )
    redirect_uri = _env_first(
        "CONFLUENCE_OAUTH_REDIRECT_URI",
        "JIRA_OAUTH_REDIRECT_URI",
        "ATLASSIAN_REDIRECT_URI",
        "NEXT_PUBLIC_CONFLUENCE_OAUTH_REDIRECT_URI",
        "NEXT_PUBLIC_JIRA_OAUTH_REDIRECT_URI",
        "NEXT_PUBLIC_ATLASSIAN_REDIRECT_URI",
    )
    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "base_url": get_atlassian_base_url(),
    }


# PUBLIC_INTERFACE
def get_frontend_base_url_default() -> str:
    """Return frontend base URL to guide redirects after auth."""
    return _env_first(
        "APP_FRONTEND_URL",
        "NEXT_PUBLIC_APP_FRONTEND_URL",
        "NEXT_PUBLIC_FRONTEND_BASE_URL",
    )
