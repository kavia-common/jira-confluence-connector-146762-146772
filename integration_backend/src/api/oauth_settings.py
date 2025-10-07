"""
Environment-driven settings for Atlassian OAuth 2.0 (3LO) with PKCE.

Required/Optional env vars:
- ATLASSIAN_CLIENT_ID (required)
- ATLASSIAN_CLIENT_SECRET (optional; Atlassian accepts PKCE-only, but include if configured)
- ATLASSIAN_REDIRECT_URI (derived automatically if BACKEND_PUBLIC_BASE_URL is provided)
- ATLASSIAN_SCOPES (optional; space-separated; fallback to defaults)
- BACKEND_PUBLIC_BASE_URL (recommended; absolute public URL for backend, used to construct redirect_uri)
- FRONTEND_BASE_URL (recommended; absolute public URL for frontend in cloud previews)
- BACKEND_CORS_ORIGINS (optional; comma-separated origins for CORS)
"""

from __future__ import annotations

# Ensure .env is loaded and logging configured before reading env
from src import startup  # noqa: F401

import logging
import os
from typing import List

_logger = logging.getLogger("config.oauth")
from .config_public import get_public_base_url, get_atlassian_redirect_uri as _central_redirect


def _normalize_base(url: str) -> str:
    """Normalize base URL to origin only (scheme://host[:port]) and remove trailing slashes.

    Guardrail:
    - If a path is present (e.g., '/docs'), strip it and log a warning.
    - Ensures BACKEND_PUBLIC_BASE_URL is never using a subpath which would break Atlassian redirect_uri matching.
    """
    if not url:
        return url
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url.strip())
        if not parsed.scheme or not parsed.netloc:
            return url.rstrip("/")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        # Log if a path/query/fragment was present and will be dropped
        if parsed.path and parsed.path not in ("", "/"):
            _logger.warning(
                "BACKEND_PUBLIC_BASE_URL contains a path segment '%s'. Using origin '%s' instead for redirect_uri construction.",
                parsed.path,
                origin,
            )
        if parsed.query or parsed.fragment:
            _logger.warning(
                "BACKEND_PUBLIC_BASE_URL contains query/fragment. These will be ignored. Using origin '%s'.",
                origin,
            )
        return origin.rstrip("/")
    except Exception:
        # Fallback to simple rstrip if parsing fails
        return url.rstrip("/")


def _build_redirect_uri_from_base(base: str) -> str:
    """Construct the standardized Atlassian callback path from the backend public base URL."""
    base = _normalize_base(base)
    if not base:
        return ""
    return f"{base}/api/oauth/atlassian/callback"


# PUBLIC_INTERFACE
def get_atlassian_oauth_config() -> dict:
    """Return a dict of Atlassian OAuth config from env.

    Behavior:
    - Prefer centralized helpers to compute backend base and redirect_uri.
    - Default callback path is '/api/oauth/atlassian/callback'.
    """
    backend_public_base = get_public_base_url()
    # Prefer centralized computed redirect; falls back to env if set explicitly
    redirect_uri = _central_redirect()

    cfg = {
        "client_id": os.getenv("ATLASSIAN_CLIENT_ID", "").strip(),
        "client_secret": os.getenv("ATLASSIAN_CLIENT_SECRET", "").strip(),
        "redirect_uri": redirect_uri,
        "scopes": os.getenv("ATLASSIAN_SCOPES", "").strip(),
        "backend_base_url": backend_public_base,
        "frontend_url": os.getenv("FRONTEND_BASE_URL", "").strip(),
    }

    redacted_client = (cfg["client_id"][:4] + "...") if cfg["client_id"] else ""
    _logger.info(
        "OAuth config loaded: client_id=%s, redirect_uri=%s, scopes_set=%s, backend_public_base=%s, frontend_base=%s",
        redacted_client,
        cfg["redirect_uri"],
        bool(cfg["scopes"]),
        cfg["backend_base_url"],
        cfg["frontend_url"],
    )

    if not cfg["client_id"]:
        _logger.error("Missing ATLASSIAN_CLIENT_ID in environment.")
    if not cfg["redirect_uri"]:
        _logger.error("Missing BACKEND_PUBLIC_BASE_URL or ATLASSIAN_REDIRECT_URI; cannot construct redirect_uri.")
    return cfg


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
    """Parse BACKEND_CORS_ORIGINS env var into list of origins for CORS.

    Behavior:
    - BACKEND_CORS_ORIGINS: comma-separated list of origins. Example:
        BACKEND_CORS_ORIGINS=https://frontend.example.com,http://localhost:3000
    - If empty, default to ["http://localhost:3000"] for local development.
    - If FRONTEND_BASE_URL or NEXT_PUBLIC_FRONTEND_BASE_URL are present, include their exact values.
    - Never return ["*"] when cookies/sessions may be used, because allow_credentials=True
      cannot be combined with wildcard origins.
    """
    raw = os.getenv("BACKEND_CORS_ORIGINS", "")
    origins = [o.strip().rstrip("/") for o in raw.split(",") if o.strip()]
    # Include detected frontend origins from env
    for key in ("FRONTEND_BASE_URL", "NEXT_PUBLIC_FRONTEND_BASE_URL"):
        v = os.getenv(key, "").strip().rstrip("/")
        if v and v not in origins:
            origins.append(v)
    if not origins:
        # Safe default for local dev; cloud previews must set BACKEND_CORS_ORIGINS explicitly
        origins = ["http://localhost:3000"]
    # Do not allow wildcard when credentials are used; filter it out just in case
    origins = [o for o in origins if o != "*"]
    return origins
