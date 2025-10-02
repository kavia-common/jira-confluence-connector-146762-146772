"""
Integration configuration for JIRA and Confluence.

NOTE: This module intentionally hard-codes credentials for demo/integration purposes
based on the task requirement. In real-world deployments, NEVER hard-code secrets.
Use environment variables or a secret manager. This file is separate to isolate the
hard-coded values and make future refactoring easier.

Expose helper getters to keep import usage clean across the codebase.
"""

from __future__ import annotations
from typing import Dict


# Demo hard-coded credentials and endpoints (replace with real ones in production)
# For JIRA (example Atlassian Cloud)
_JIRA_CREDENTIALS: Dict[str, str] = {
    "base_url": "https://your-company.atlassian.net",
    "client_id": "demo-jira-client-id",
    "client_secret": "demo-jira-client-secret",
    "access_token": "demo-jira-access-token",
}

# For Confluence (example Atlassian Cloud)
_CONFLUENCE_CREDENTIALS: Dict[str, str] = {
    "base_url": "https://your-company.atlassian.net/wiki",
    "client_id": "demo-confluence-client-id",
    "client_secret": "demo-confluence-client-secret",
    "access_token": "demo-confluence-access-token",
}


# PUBLIC_INTERFACE
def get_jira_credentials() -> Dict[str, str]:
    """Return hard-coded JIRA credentials and base URL."""
    return dict(_JIRA_CREDENTIALS)


# PUBLIC_INTERFACE
def get_confluence_credentials() -> Dict[str, str]:
    """Return hard-coded Confluence credentials and base URL."""
    return dict(_CONFLUENCE_CREDENTIALS)
