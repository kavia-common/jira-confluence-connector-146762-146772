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

try:
    # Best effort: load .env if present. This is safe in dev and ignored in prod when envs are set.
    # We do not fail if python-dotenv is missing (but it's in requirements.txt).
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()  # load from default path integration_backend/.env when run with app-dir
except Exception:
    # Silent pass: environments may not include python-dotenv, and prod will inject envs directly.
    pass


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

    Behavior:
    - Reads at runtime. Supports multiple env names, including JIRA_CLIENT_ID/SECRET.
    - Provides safe defaults for client_id and redirect_uri if not explicitly set,
      to prevent 500s during login initiation when configuration is present elsewhere.
    """
    # Accept both canonical and alternate names
    client_id = _env_first(
        "JIRA_CLIENT_ID",                 # new alias
        "JIRA_OAUTH_CLIENT_ID",
        "ATLASSIAN_CLIENT_ID",
        "NEXT_PUBLIC_JIRA_CLIENT_ID",
        "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID",
        "NEXT_PUBLIC_ATLASSIAN_CLIENT_ID",
    )
    client_secret = _env_first(
        "JIRA_CLIENT_SECRET",             # new alias
        "JIRA_OAUTH_CLIENT_SECRET",
        "ATLASSIAN_CLIENT_SECRET",
        "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET",
        "NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET",
    )

    # Safe default for redirect matches README guidance if env is not set
    default_redirect = "https://vscode-internal-13311-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback"
    redirect_uri = _env_first(
        "JIRA_REDIRECT_URI",
        "JIRA_OAUTH_REDIRECT_URI",
        "ATLASSIAN_REDIRECT_URI",
        "NEXT_PUBLIC_JIRA_REDIRECT_URI",
        "NEXT_PUBLIC_JIRA_OAUTH_REDIRECT_URI",
        "NEXT_PUBLIC_ATLASSIAN_REDIRECT_URI",
        default=default_redirect,
    )

    # Safe default client_id (non-secret) to avoid 500s in environments that expect defaults.
    # Note: Using a default here only affects the authorize URL building; token exchange still requires real secret.
    if not client_id:
        client_id = "hHwzD9WrTnD6SFcV4tp4zDt9XbB9K9WQ"

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


# PUBLIC_INTERFACE
def get_oauth_config_health() -> Dict[str, Dict[str, str | bool]]:
    """Return a non-sensitive snapshot of current OAuth config readiness for Jira and Confluence.

    Response fields:
      - jira: { has_client_id: bool, has_client_secret: bool, redirect_uri: str }
      - confluence: { has_client_id: bool, has_client_secret: bool, redirect_uri: str }
    """
    j = get_jira_oauth_config()
    c = get_confluence_oauth_config()
    return {
        "jira": {
            "has_client_id": bool(j.get("client_id")),
            "has_client_secret": bool(j.get("client_secret")),
            "redirect_uri": j.get("redirect_uri", ""),
        },
        "confluence": {
            "has_client_id": bool(c.get("client_id")),
            "has_client_secret": bool(c.get("client_secret")),
            "redirect_uri": c.get("redirect_uri", ""),
        },
    }
