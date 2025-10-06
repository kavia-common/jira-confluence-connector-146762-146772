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


def _normalize_base(url: str) -> str:
    """Normalize base URL to not end with a trailing slash."""
    return url.rstrip("/") if url else url


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
    - Prefer constructing redirect_uri as BACKEND_PUBLIC_BASE_URL + '/api/oauth/atlassian/callback'
    - If ATLASSIAN_REDIRECT_URI is set, validate it matches the constructed one and log a warning on mismatch.
    """
    backend_public_base = os.getenv("BACKEND_PUBLIC_BASE_URL", "").strip() or os.getenv("BACKEND_BASE_URL", "").strip()
    constructed_redirect = _build_redirect_uri_from_base(backend_public_base)

    env_redirect = os.getenv("ATLASSIAN_REDIRECT_URI", "").strip()
    # Choose redirect_uri:
    # - If we have a constructed one, use it as source of truth
    # - Else fall back to env_redirect (legacy)
    chosen_redirect = constructed_redirect or env_redirect

    cfg = {
        "client_id": os.getenv("ATLASSIAN_CLIENT_ID", "").strip(),
        "client_secret": os.getenv("ATLASSIAN_CLIENT_SECRET", "").strip(),
        "redirect_uri": chosen_redirect,
        "scopes": os.getenv("ATLASSIAN_SCOPES", "").strip(),
        "backend_base_url": backend_public_base,
        "frontend_url": os.getenv("FRONTEND_BASE_URL", "").strip(),
    }

    # Validation and diagnostics
    redacted_client = (cfg["client_id"][:4] + "...") if cfg["client_id"] else ""
    mismatch_note = ""
    if constructed_redirect and env_redirect and constructed_redirect != env_redirect:
        mismatch_note = f" (WARNING: ATLASSIAN_REDIRECT_URI env value '{env_redirect}' does not match constructed '{constructed_redirect}'; using constructed value.)"
        _logger.warning(
            "Configured ATLASSIAN_REDIRECT_URI (%s) differs from constructed from BACKEND_PUBLIC_BASE_URL (%s). Using constructed value.",
            env_redirect,
            constructed_redirect,
        )

    _logger.info(
        "OAuth config loaded: client_id=%s, redirect_uri=%s, scopes_set=%s, backend_public_base=%s, frontend_base=%s%s",
        redacted_client,
        cfg["redirect_uri"],
        bool(cfg["scopes"]),
        cfg["backend_base_url"],
        cfg["frontend_url"],
        mismatch_note,
    )

    # Fail-fast hints in logs if critical values missing (routes will still raise HTTPException)
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
    """Parse BACKEND_CORS_ORIGINS env var into list of origins for CORS."""
    raw = os.getenv("BACKEND_CORS_ORIGINS", "")
    origins = [o.strip() for o in raw.split(",") if o.strip()]
    if not origins:
        # Explicitly avoid localhost defaults; require env to be set in cloud
        # Fallback to '*' only for unrestricted previews. Prefer setting BACKEND_CORS_ORIGINS.
        origins = ["*"]
    return origins
