"""
Integration configuration for JIRA and Confluence.

This module provides backward-compatible helpers but NO hard-coded secrets.
All sensitive values must be provided via environment variables and handled by oauth_config.

Kept for compatibility with earlier imports. Prefer using src.api.oauth_config instead.
"""
from __future__ import annotations
from typing import Dict
from .oauth_config import get_jira_oauth_config, get_confluence_oauth_config


# PUBLIC_INTERFACE
def get_jira_credentials() -> Dict[str, str]:
    """Return JIRA OAuth config (no secrets exposed to logs)."""
    cfg = get_jira_oauth_config()
    # Expose only non-sensitive parts in this "credentials" shim
    return {"base_url": cfg.get("base_url", "")}


# PUBLIC_INTERFACE
def get_confluence_credentials() -> Dict[str, str]:
    """Return Confluence OAuth config (no secrets exposed to logs)."""
    cfg = get_confluence_oauth_config()
    return {"base_url": cfg.get("base_url", "")}
