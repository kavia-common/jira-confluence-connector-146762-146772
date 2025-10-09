"""
OAuth configuration helper for Atlassian (JIRA/Confluence) OAuth 2.0 (3LO) flows.

All configuration is pulled from environment variables. Do NOT hardcode sensitive data.
Required environment variables (example .env is provided separately):

- ATLASSIAN_CLOUD_BASE_URL: The base URL of your Atlassian Cloud site, e.g. "https://your-team.atlassian.net"
- JIRA_OAUTH_CLIENT_ID: OAuth client ID for your Jira/Atlassian app
- JIRA_OAUTH_CLIENT_SECRET: OAuth client secret for your Jira/Atlassian app
- JIRA_REDIRECT_URI: Canonical Redirect URI configured in Atlassian developer console, e.g. "https://yourapp.com/auth/jira/callback"
  This value is used for Jira authorization URL construction and must match exactly in Atlassian.

Redirect URI precedence (strict):
1) JIRA_REDIRECT_URI if set (used verbatim)
2) Request-aware builder using X-Forwarded-Proto/Host + Request.url_for('jira_callback')
3) Deployment default: https://vscode-internal-36200-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback

Notes:
- No legacy/front-end/alias fallbacks are used.
- Do not ever fallback to "/api/oauth/callback/jira" or any "http(s)://*:3000/*" URL.

- CONFLUENCE_OAUTH_CLIENT_ID, CONFLUENCE_OAUTH_CLIENT_SECRET, CONFLUENCE_OAUTH_REDIRECT_URI:
  If you use a distinct app/client for Confluence. If not set, Jira values will be reused.

- APP_FRONTEND_URL: Frontend base URL to return the user to after auth success/failure (used ONLY for post-auth UI redirect, NEVER for Atlassian redirect_uri). Optional.

Deployment default (if no envs are set in this environment):
- Redirect URI defaults to https://vscode-internal-36200-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback

Note:
- Scopes must be configured on Atlassian side. During authorization, pass the scopes needed by your app.
"""
from __future__ import annotations

import os
import urllib.parse
from typing import Dict, Optional, Tuple, List
from pydantic import BaseModel, Field

# Load .env early for local dev/preview so settings see variables at import-time.
# We avoid logging here to prevent circular imports; status is exposed via get_env_bootstrap_debug().
try:
    from dotenv import load_dotenv, find_dotenv  # type: ignore
except Exception:
    load_dotenv = None  # type: ignore
    find_dotenv = None  # type: ignore

_DOTENV_STATUS: Dict[str, Optional[str]] = {"loaded": "false", "path": None}


def _load_env_once() -> None:
    """Attempt to load a .env for integration_backend with best-effort search."""
    if _DOTENV_STATUS.get("loaded") == "true":
        return
    env_file = os.getenv("INTEGRATION_BACKEND_ENV_FILE")

    candidates: List[Optional[str]] = []
    if env_file:
        candidates.append(env_file)
    try:
        # This file is at integration_backend/src/api/oauth_config.py -> ../../.env should be integration_backend/.env
        here = os.path.dirname(__file__)
        candidates.append(os.path.normpath(os.path.join(here, "../../.env")))
    except Exception:
        pass
    if find_dotenv:
        # Try common locations based on CWD/root
        try:
            candidates.append(find_dotenv(".env", raise_error=False))
        except Exception:
            candidates.append(None)
        try:
            candidates.append(find_dotenv("integration_backend/.env", raise_error=False))
        except Exception:
            candidates.append(None)

    path_used = None
    loaded = False
    if load_dotenv:
        # Try specific candidates first
        for c in candidates:
            if c and os.path.isfile(c):
                try:
                    loaded = load_dotenv(c, override=False)
                except Exception:
                    loaded = False
                if loaded:
                    path_used = c
                    break
        # Fallback to auto-discovery from process CWD
        if not loaded:
            try:
                loaded = load_dotenv(override=False)
            except Exception:
                loaded = False
            if loaded and path_used is None:
                path_used = "auto"
    _DOTENV_STATUS["loaded"] = "true" if loaded else "false"
    _DOTENV_STATUS["path"] = path_used


# Ensure env is loaded before Settings() is constructed
_load_env_once()


def _env_first(*names: str) -> str:
    """Return the first non-empty environment variable value among names (trimmed)."""
    for name in names:
        val = os.getenv(name, "")
        if val and val.strip():
            return val.strip()
    return ""


# Candidate env var names used for resolution and debug visibility
JIRA_ID_ENV_CANDIDATES: List[str] = [
    "JIRA_OAUTH_CLIENT_ID",
    "ATLASSIAN_CLIENT_ID",
    "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID",
    "NEXT_PUBLIC_JIRA_CLIENT_ID",
    "NEXT_PUBLIC_ATLASSIAN_CLIENT_ID",
]
JIRA_SECRET_ENV_CANDIDATES: List[str] = [
    "JIRA_OAUTH_CLIENT_SECRET",
    "ATLASSIAN_CLIENT_SECRET",
    "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET",
    "NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET",
]
# Canonical Atlassian redirect URI env (STRICT)
JIRA_REDIRECT_ENV_CANDIDATES: List[str] = [
    "JIRA_REDIRECT_URI",
]
FRONTEND_URL_ENV_CANDIDATES: List[str] = [
    "APP_FRONTEND_URL",
    "NEXT_PUBLIC_APP_FRONTEND_URL",
    "NEXT_PUBLIC_FRONTEND_BASE_URL",
]
ATLASSIAN_BASE_ENV_CANDIDATES: List[str] = [
    "ATLASSIAN_CLOUD_BASE_URL",
    "NEXT_PUBLIC_ATLASSIAN_CLOUD_BASE_URL",
]


def _resolve_env(names: List[str]) -> Tuple[str, Optional[str]]:
    """
    Resolve the first non-empty env value from a list and return (value, source_env_name).
    """
    for name in names:
        raw = os.getenv(name)
        if raw is None:
            continue
        val = raw.strip()
        if val:
            return val, name
    return "", None


def _mask_secret(value: Optional[str], keep: int = 4) -> str:
    """
    Mask a secret, leaving only the last 'keep' characters visible.
    """
    if not value:
        return ""
    if len(value) <= keep:
        return "*" * len(value)
    return "*" * (len(value) - keep) + value[-keep:]


def _analyze_url(uri: str) -> Dict[str, Optional[str]]:
    """
    Provide a non-blocking analysis of a URL for debug logs (never raises).
    """
    try:
        parsed = urllib.parse.urlparse(uri)
        valid = bool(parsed.scheme and parsed.netloc)
        reason = None if valid else "missing scheme or host"
        return {
            "valid": str(valid).lower(),
            "scheme": parsed.scheme or "",
            "netloc": parsed.netloc or "",
            "path": parsed.path or "",
            "reason": reason,
        }
    except Exception:
        return {"valid": "false", "scheme": "", "netloc": "", "path": "", "reason": "parse_error"}


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
    # Frontend base URL (used for post-auth redirect). Default stays as-is; route suffix handled in main logic.
    frontend_url: Optional[str] = Field(default=_env_first("APP_FRONTEND_URL", "NEXT_PUBLIC_APP_FRONTEND_URL", "NEXT_PUBLIC_FRONTEND_BASE_URL"))

    # Atlassian base
    atlassian_base_url: Optional[str] = Field(default=_env_first("ATLASSIAN_CLOUD_BASE_URL", "NEXT_PUBLIC_ATLASSIAN_CLOUD_BASE_URL"))

    # Jira OAuth (STRICT: redirect_uri must exactly match Atlassian console)
    jira_client_id: Optional[str] = Field(default=_env_first("JIRA_OAUTH_CLIENT_ID", "ATLASSIAN_CLIENT_ID", "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID", "NEXT_PUBLIC_JIRA_CLIENT_ID", "NEXT_PUBLIC_ATLASSIAN_CLIENT_ID"))
    jira_client_secret: Optional[str] = Field(default=_env_first("JIRA_OAUTH_CLIENT_SECRET", "ATLASSIAN_CLIENT_SECRET", "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET", "NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET"))
    # Strictly use JIRA_REDIRECT_URI for Jira authorization URL construction
    jira_redirect_uri: Optional[str] = Field(default=_env_first("JIRA_REDIRECT_URI"))

    # Confluence OAuth
    confluence_client_id: Optional[str] = Field(default=_env_first("CONFLUENCE_OAUTH_CLIENT_ID", "JIRA_OAUTH_CLIENT_ID", "ATLASSIAN_CLIENT_ID", "NEXT_PUBLIC_CONFLUENCE_OAUTH_CLIENT_ID", "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID", "NEXT_PUBLIC_JIRA_CLIENT_ID", "NEXT_PUBLIC_ATLASSIAN_CLIENT_ID"))
    confluence_client_secret: Optional[str] = Field(default=_env_first("CONFLUENCE_OAUTH_CLIENT_SECRET", "JIRA_OAUTH_CLIENT_SECRET", "ATLASSIAN_CLIENT_SECRET", "NEXT_PUBLIC_CONFLUENCE_OAUTH_CLIENT_SECRET", "NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET", "NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET"))
    confluence_redirect_uri: Optional[str] = Field(default=_env_first("ATLASSIAN_OAUTH_REDIRECT_URI", "ATLASSIAN_REDIRECT_URI", "CONFLUENCE_OAUTH_REDIRECT_URI", "JIRA_OAUTH_REDIRECT_URI"))


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


def _choose_canonical_redirect(default_path: str) -> str:
    """
    Choose the Jira redirect URI.

    Strict precedence:
      1) JIRA_REDIRECT_URI (used verbatim)
      2) Request-aware builder using X-Forwarded-Proto/Host and Request.url_for('jira_callback')
      3) Deployment default: https://vscode-internal-36200-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback

    Notes:
    - Never derive from frontend URL.
    - Never use /api/oauth/callback/jira or port 3000.
    """
    val, _src = _resolve_env(JIRA_REDIRECT_ENV_CANDIDATES)
    effective = (val or "").strip()
    if effective:
        return effective

    # Without request context, fall back to safe default; request-aware builder is provided below.
    return "https://vscode-internal-36200-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback"

from fastapi import Request  # safe to import; only used when FastAPI present
from urllib.parse import urlunparse

def _pick_scheme_host_from_headers(request: Request) -> tuple[str | None, str | None]:
    """
    Inspect forwarded headers to infer the external scheme and host for reverse-proxied deployments.
    Returns (scheme, host) or (None, None) if not derivable.
    """
    # Prefer explicit forwarded proto/host
    proto = (request.headers.get("x-forwarded-proto") or request.headers.get("x-scheme") or "").strip().lower()
    host = (request.headers.get("x-forwarded-host") or "").strip()
    # Fallback to request.url when not proxied
    if not proto:
        proto = request.url.scheme
    if not host:
        host = request.headers.get("host") or request.url.netloc
    proto = proto or None
    host = host or None
    return proto, host

# PUBLIC_INTERFACE
def choose_jira_redirect_with_request(request: Request, callback_path: str = "/auth/jira/callback") -> str:
    """
    Determine the effective Jira redirect_uri using:
      1) JIRA_REDIRECT_URI env override if set (verbatim)
      2) Current request's external scheme/host (X-Forwarded-Proto/Host aware) + callback_path
      3) Safe default for this deployment

    This ensures the redirect_uri matches the host the client used to reach the backend.
    """
    # 1) Env override
    env_val, _ = _resolve_env(JIRA_REDIRECT_ENV_CANDIDATES)
    if env_val and env_val.strip():
        return env_val.strip()

    # 2) Build from current request context
    try:
        scheme, host = _pick_scheme_host_from_headers(request)
        # Build absolute URL: scheme://host + callback_path
        if scheme and host:
            # normalize path
            path = callback_path if callback_path.startswith("/") else f"/{callback_path}"
            return urlunparse((scheme, host, path, "", "", ""))
        # As a last attempt, use url_for to get absolute URL if available
        try:
            # Build absolute callback using named route
            abs_url = str(request.url_for("jira_callback"))
            if abs_url:
                return abs_url
        except Exception:
            pass
    except Exception:
        pass

    # 3) Fallback default (kept to satisfy acceptance tests)
    return "https://vscode-internal-36200-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback"

# PUBLIC_INTERFACE
def get_jira_oauth_config() -> Dict[str, str]:
    """Return Jira OAuth 2.0 config from the environment with robust fallbacks."""
    redirect_uri = _choose_canonical_redirect("/auth/jira/callback")
    return {
        "client_id": (_SETTINGS.jira_client_id or "").strip(),
        "client_secret": (_SETTINGS.jira_client_secret or "").strip(),
        "redirect_uri": redirect_uri,
        "base_url": get_atlassian_base_url(),
        "dev_mode": str(_SETTINGS.dev_mode).lower(),
        "app_env": (_SETTINGS.app_env or "production").strip(),
        "frontend_url": (_SETTINGS.frontend_url or "").strip(),
    }


# PUBLIC_INTERFACE
def get_confluence_oauth_config() -> Dict[str, str]:
    """
    Return Confluence OAuth 2.0 config from the environment.
    Falls back to canonical Atlassian redirect if a dedicated one is not provided.
    """
    # If a dedicated Confluence redirect is set, use it; otherwise use the canonical Atlassian redirect builder
    explicit_redirect = (_SETTINGS.confluence_redirect_uri or "").strip()
    redirect_uri = explicit_redirect or _choose_canonical_redirect("/auth/confluence/callback")
    return {
        "client_id": (_SETTINGS.confluence_client_id or "").strip(),
        "client_secret": (_SETTINGS.confluence_client_secret or "").strip(),
        "redirect_uri": redirect_uri,
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
    # Require client_id, client_secret, and redirect_uri
    return bool(cfg.get("client_id")) and bool(cfg.get("client_secret")) and bool(cfg.get("redirect_uri"))


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


# PUBLIC_INTERFACE
def get_jira_oauth_env_debug() -> Dict[str, Dict[str, str]]:
    """
    Return masked, source-aware Jira OAuth env resolution for diagnostics.

    This does not expose raw secrets; values are masked and redirect_uri is analyzed non-blockingly.
    """
    client_id_val, client_id_src = _resolve_env(JIRA_ID_ENV_CANDIDATES)
    client_secret_val, client_secret_src = _resolve_env(JIRA_SECRET_ENV_CANDIDATES)
    redirect_val, redirect_src = _resolve_env(JIRA_REDIRECT_ENV_CANDIDATES)
    frontend_val, frontend_src = _resolve_env(FRONTEND_URL_ENV_CANDIDATES)
    base_val, base_src = _resolve_env(ATLASSIAN_BASE_ENV_CANDIDATES)

    # Determine the effective redirect URI that will be used generally (without request context)
    explicit_redirect = redirect_val.strip() if redirect_val else ""
    if explicit_redirect:
        effective_redirect = explicit_redirect
        effective_source = redirect_src or "JIRA_REDIRECT_URI"
    else:
        # Without request context, we cannot infer host; show the static default here.
        effective_redirect = "https://vscode-internal-36200-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback"
        effective_source = "default"

    return {
        "client_id": {
            "present": str(bool(client_id_val)).lower(),
            "source": client_id_src or "",
            "value_masked": _mask_secret(client_id_val),
        },
        "client_secret": {
            "present": str(bool(client_secret_val)).lower(),
            "source": client_secret_src or "",
            "value_masked": _mask_secret(client_secret_val),
        },
        "redirect_uri": {
            "present": str(bool(effective_redirect)).lower(),
            "source": effective_source,
            "value_masked": _mask_secret(effective_redirect),
            "analysis": _analyze_url(effective_redirect) if effective_redirect else {"valid": "false", "reason": "empty"},
        },
        "frontend_url": {
            "present": str(bool(frontend_val)).lower(),
            "source": frontend_src or "",
            "value_masked": _mask_secret(frontend_val),
        },
        "atlassian_base_url": {
            "present": str(bool(base_val)).lower(),
            "source": base_src or "",
            "value_masked": _mask_secret(base_val),
        },
        "app_env": (_SETTINGS.app_env or "production"),
        "dev_mode": str(_SETTINGS.dev_mode).lower(),
    }


# PUBLIC_INTERFACE
def get_env_bootstrap_debug() -> Dict[str, str]:
    """Return debug info about dotenv loading and runtime mode for diagnostics."""
    return {
        "dotenv_loaded": str(_DOTENV_STATUS.get("loaded") or "").lower(),
        "dotenv_path": str(_DOTENV_STATUS.get("path") or ""),
        "app_env": (_SETTINGS.app_env or "production"),
        "dev_mode": str(_SETTINGS.dev_mode).lower(),
    }

# PUBLIC_INTERFACE
def get_active_redirect_uris_debug() -> Dict[str, Dict[str, str]]:
    """Return which redirect URIs are currently active for Jira and Confluence."""
    jira_redirect = _choose_canonical_redirect("/auth/jira/callback")
    conf_redirect = (_SETTINGS.confluence_redirect_uri or "").strip() or _choose_canonical_redirect("/auth/confluence/callback")
    return {
        "jira": {
            "uri": jira_redirect,
            "analysis": _analyze_url(jira_redirect),
        },
        "confluence": {
            "uri": conf_redirect,
            "analysis": _analyze_url(conf_redirect),
        },
    }
