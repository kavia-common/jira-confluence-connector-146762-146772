"""
Environment-driven settings for Atlassian OAuth 2.0 (3LO) with PKCE.

Required/Optional env vars:
- ATLASSIAN_CLIENT_ID (required)
- ATLASSIAN_CLIENT_SECRET (optional; Atlassian accepts PKCE-only, but include if configured)
- ATLASSIAN_REDIRECT_URI (required; must exactly match Atlassian app setting)
- ATLASSIAN_SCOPES (optional; space-separated; fallback to defaults)
- BACKEND_BASE_URL (recommended; absolute public URL for backend in cloud previews)
- FRONTEND_BASE_URL (recommended; absolute public URL for frontend in cloud previews)
- BACKEND_CORS_ORIGINS (optional; comma-separated origins for CORS)
"""

from __future__ import annotations

import os
from typing import List


# PUBLIC_INTERFACE
def get_atlassian_oauth_config() -> dict:
    """Return a dict of Atlassian OAuth config from env."""
    return {
        "client_id": os.getenv("ATLASSIAN_CLIENT_ID", "").strip(),
        "client_secret": os.getenv("ATLASSIAN_CLIENT_SECRET", "").strip(),
        # IMPORTANT: Do not derive redirect URI; must exactly equal Atlassian app setting
        "redirect_uri": os.getenv("ATLASSIAN_REDIRECT_URI", "").strip(),
        "scopes": os.getenv("ATLASSIAN_SCOPES", "").strip(),
        # Public URLs for this deployment (used only for final UI redirects or docs)
        "backend_base_url": os.getenv("BACKEND_BASE_URL", "").strip(),
        "frontend_url": os.getenv("FRONTEND_BASE_URL", "").strip(),
    }


# PUBLIC_INTERFACE
def get_default_scopes() -> str:
    """Provide a reasonable default scope set if ATLASSIAN_SCOPES is not set."""
    # offline_access is required to receive refresh_token
    defaults = [
        "read:jira-work",
        "read:jira-user",
        "read:confluence-content.all",
        "read:confluence-space.summary",
        "offline_access",
    ]
    return " ".join(defaults)


# PUBLIC_INTERFACE
def get_cors_origins() -> List[str]:
    """Parse BACKEND_CORS_ORIGINS env var into list of origins for CORS."""
    raw = os.getenv("BACKEND_CORS_ORIGINS", "")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if not origins:
        # Explicitly avoid localhost defaults; require env to be set in cloud
        # Fallback to '*' only for unrestricted previews. Prefer setting BACKEND_CORS_ORIGINS.
        origins = ["*"]
    return origins
