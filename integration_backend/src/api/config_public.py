"""
Centralized configuration for public URLs and OAuth redirect URIs.

This module exposes helpers to compute the backend's public base URL and the
Atlassian OAuth redirect URI using environment variables. It avoids hardcoding
hostnames/ports and ensures consistent construction of redirect URIs.

Env vars:
- BACKEND_PUBLIC_BASE_URL: The public origin for the backend (scheme://host[:port])
  Example: https://your-backend.example.com:3001  (no path)
- ATLASSIAN_REDIRECT_URI: Optional. If not provided, computed as:
  {BACKEND_PUBLIC_BASE_URL}/api/oauth/atlassian/callback

If BACKEND_PUBLIC_BASE_URL includes a path or query, it will be normalized to origin-only.
"""
from __future__ import annotations

import os
import logging
from urllib.parse import urlparse

_logger = logging.getLogger("config.public")


def _normalize_origin(url: str) -> str:
    """
    Reduce a URL to origin-only (scheme://host[:port]) with no trailing slash.
    Logs a warning if a path, query, or fragment was present.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip())
        if not parsed.scheme or not parsed.netloc:
            # Not a standard URL; return as-is without trailing slash
            return url.strip().rstrip("/")
        origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        if parsed.path and parsed.path not in ("", "/"):
            _logger.warning(
                "BACKEND_PUBLIC_BASE_URL contains a path '%s'. Using origin '%s' instead.",
                parsed.path,
                origin,
            )
        if parsed.query or parsed.fragment:
            _logger.warning(
                "BACKEND_PUBLIC_BASE_URL contains query or fragment; ignoring them. Using origin '%s'.",
                origin,
            )
        return origin
    except Exception:
        return url.strip().rstrip("/")


# PUBLIC_INTERFACE
def get_public_base_url() -> str:
    """
    Return the backend's public base URL origin, normalized.

    Reads BACKEND_PUBLIC_BASE_URL, or falls back to BACKEND_BASE_URL if present.
    """
    raw = os.getenv("BACKEND_PUBLIC_BASE_URL", "").strip() or os.getenv("BACKEND_BASE_URL", "").strip()
    origin = _normalize_origin(raw)
    if raw and raw.rstrip("/") != origin:
        _logger.warning("Adjusted backend base URL from '%s' to '%s' (origin-only).", raw, origin)
    return origin


# PUBLIC_INTERFACE
def get_atlassian_redirect_uri() -> str:
    """
    Compute the Atlassian OAuth redirect URI.

    If ATLASSIAN_REDIRECT_URI is set, it is returned as-is.
    Otherwise, derive it from BACKEND_PUBLIC_BASE_URL as:
        {BACKEND_PUBLIC_BASE_URL}/api/oauth/atlassian/callback
    """
    env_redirect = os.getenv("ATLASSIAN_REDIRECT_URI", "").strip()
    if env_redirect:
        return env_redirect
    base = get_public_base_url()
    return f"{base}/api/oauth/atlassian/callback" if base else ""
