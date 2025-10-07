"""
Aligned OAuth endpoints for Atlassian with return_url handling.

This router adds:
- GET /api/oauth/atlassian/login: Accepts ?return_url=<absolute URL>, creates a random state,
  persists state->return_url with a TTL, and redirects (307) to Atlassian authorize URL.
- GET /api/oauth/atlassian/callback: Validates state, exchanges code for tokens, persists tokens (session),
  and redirects back to saved return_url with result and message.

Notes:
- Uses in-memory stores for (state->return_url) and session token storage (see oauth_pkce.py).
  For production, replace with Redis or a database-backed store.
- Do NOT hardcode secrets. All configuration is via environment variables:
  ATLASSIAN_CLIENT_ID, ATLASSIAN_CLIENT_SECRET (optional with PKCE),
  ATLASSIAN_REDIRECT_URI, ATLASSIAN_SCOPES (optional).
- Ensure BACKEND_CORS_ORIGINS includes your frontend origin.

OpenAPI is provided via FastAPI decorators.
"""
from __future__ import annotations

import logging
import urllib.parse
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse, JSONResponse

from .oauth_settings import get_atlassian_oauth_config, get_default_scopes
from .oauth_pkce import (
    generate_code_verifier,
    generate_code_challenge,
    generate_state,
    get_or_create_session_id,
    save_session,
    save_tokens,
    get_session,
    SessionData,
)
from .redis_client import (
    save_oauth_state,
    consume_oauth_state,
    export_oauth_state_diagnostics,
    get_state_ttl_seconds,
    has_redis,
)
import os

logger = logging.getLogger("oauth.return")

router = APIRouter()




def _is_absolute_url(url: str | None) -> bool:
    """Basic absolute URL validation."""
    if not url:
        return False
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False


def _encode_message(message: str) -> str:
    """URL encode message for safe use in query parameters."""
    return urllib.parse.quote_plus(message)


def _mask_state(state: str) -> str:
    """Return a masked representation of a state for logs."""
    if not state:
        return ""
    return state[:6] + "..." + state[-4:]


# PUBLIC_INTERFACE
@router.get(
    "/api/oauth/atlassian/login",
    tags=["Auth"],
    summary="Start Atlassian OAuth login (with return_url)",
    description="Accepts return_url, generates state and PKCE, stores mapping, and redirects to Atlassian authorize.",
    responses={
        307: {"description": "Redirect to Atlassian authorize"},
        400: {"description": "Invalid return_url"},
        500: {"description": "OAuth configuration missing"},
    },
)
async def oauth_atlassian_login(request: Request, return_url: Optional[str] = None, scope: Optional[str] = None):
    """
    PUBLIC_INTERFACE
    Start Atlassian OAuth 2.0 (3LO) login flow.

    Query params:
      - return_url: Absolute URL to redirect the user back to after callback. Required and must be absolute.
      - scope: Optional space-separated scope overrides. If omitted, uses ATLASSIAN_SCOPES or a default set.

    Returns:
      - 307 redirect to Atlassian authorize URL with PKCE.
    """
    cfg = get_atlassian_oauth_config()
    client_id = cfg.get("client_id")
    redirect_uri = cfg.get("redirect_uri")
    backend_base = cfg.get("backend_base_url")
    scopes = scope or cfg.get("scopes") or get_default_scopes()

    # Fail fast with actionable errors
    missing = []
    if not client_id:
        missing.append("ATLASSIAN_CLIENT_ID")
    if not redirect_uri:
        hint = f"{(backend_base.rstrip('/') + '/api/oauth/atlassian/callback') if backend_base else 'BACKEND_PUBLIC_BASE_URL + /api/oauth/atlassian/callback'}"
        raise HTTPException(
            status_code=500,
            detail=f"Missing redirect_uri. Set BACKEND_PUBLIC_BASE_URL so redirect_uri resolves to {hint}, or set ATLASSIAN_REDIRECT_URI explicitly.",
        )
    if missing:
        raise HTTPException(status_code=500, detail=f"Missing environment variables: {', '.join(missing)}")

    if not _is_absolute_url(return_url):
        raise HTTPException(status_code=400, detail="Invalid or missing return_url; must be absolute (http/https).")

    # Log incoming request context and environment
    logger.info(
        "OAuth start request: host=%s path=%s query=%s backend_base=%s redirect_uri=%s hasRedis=%s ttl=%s",
        request.headers.get("host", ""),
        request.url.path,
        str(request.url.query),
        backend_base or "",
        redirect_uri or "",
        has_redis(),
        get_state_ttl_seconds(),
    )

    # PKCE and state
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    csrf_state = generate_state()

    # Persist session data and state mapping (with TTL)
    existing_sid = request.cookies.get("sid")
    session_id = get_or_create_session_id(existing_sid)
    save_session(session_id, SessionData(state=csrf_state, code_verifier=code_verifier, token_set=None))
    try:
        save_oauth_state(
            csrf_state,
            {
                "return_url": return_url,
                "code_verifier": "***",  # avoid storing raw verifier; session holds it
            },
        )
        logger.info(
            "Saved oauth state: key=%s backend=%s ttl=%s return_url_host=%s",
            _mask_state(csrf_state),
            "redis" if has_redis() else "memory",
            get_state_ttl_seconds(),
            urllib.parse.urlparse(return_url).netloc if return_url else "",
        )
    except Exception as e:
        logger.exception("Failed saving oauth state: %s", e)
        raise HTTPException(status_code=500, detail="Internal error saving OAuth state")

    # Build authorize URL
    authorize_url = "https://auth.atlassian.com/authorize"
    params = {
        "audience": "api.atlassian.com",
        "client_id": client_id,
        "scope": scopes,
        "redirect_uri": redirect_uri,
        "state": csrf_state,
        "response_type": "code",
        "prompt": "consent",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    url = f"{authorize_url}?{urllib.parse.urlencode(params)}"

    logger.info(
        "Redirecting to Atlassian authorize: has_state=%s scopes_len=%d",
        True,
        len((scopes or '').split()),
    )

    # Determine if the client expects a JSON response (XHR/fetch) instead of a 307 redirect.
    # We support both Accept-based detection and X-Requested-With (if present).
    accept = (request.headers.get("accept") or "").lower()
    xrw = (request.headers.get("x-requested-with") or "").lower()
    wants_json = ("application/json" in accept) or (xrw == "xmlhttprequest")

    if wants_json:
        # Return JSON payload with the Atlassian authorization URL and set session cookie.
        resp = JSONResponse({"url": url})
        resp.set_cookie(
            key="sid",
            value=session_id,
            httponly=True,
            secure=True,
            samesite="lax",
            path="/",
            max_age=60 * 60 * 24 * 14,
        )
        return resp

    # Default: issue a redirect for normal browser navigations
    resp = RedirectResponse(url, status_code=307)
    # Ensure cookie is set for session continuity
    resp.set_cookie(
        key="sid",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=60 * 60 * 24 * 14,
    )
    return resp


# PUBLIC_INTERFACE
@router.get(
    "/api/oauth/atlassian/callback",
    tags=["Auth"],
    summary="Atlassian OAuth callback (return_url redirect)",
    description="Validates state, exchanges code for tokens, and redirects back to the original return_url with result and message.",
    responses={
        307: {"description": "Redirect back to return_url with result"},
        400: {"description": "Missing or invalid code/state, or session expired"},
        500: {"description": "OAuth configuration missing"},
    },
)
async def oauth_atlassian_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None):
    """
    PUBLIC_INTERFACE
    Atlassian callback handler to complete OAuth login.

    Behavior:
    - Validates 'state' against stored session and retrieves the saved return_url.
    - Exchanges 'code' for tokens with Atlassian using PKCE.
    - Persists tokens in the session (in-memory demo).
    - Redirects back to return_url with:
        ?result=success
      or
        ?result=error&message=<url-encoded message>
    """
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state")

    cfg = get_atlassian_oauth_config()
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret") or None
    redirect_uri = cfg.get("redirect_uri")

    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Atlassian OAuth not configured. Set ATLASSIAN_CLIENT_ID and ATLASSIAN_REDIRECT_URI.")

    # Log incoming callback context
    session_id = request.cookies.get("sid")
    logger.info(
        "OAuth callback: host=%s path=%s query=%s hasRedis=%s state=%s cookie_present=%s",
        request.headers.get("host", ""),
        request.url.path,
        str(request.url.query),
        has_redis(),
        _mask_state(state or ""),
        bool(session_id),
    )

    # Lookup session and state mapping first
    sess = get_session(session_id) if session_id else None

    # Load and consume state payload (one-time)
    state_payload = consume_oauth_state(state)
    if not state_payload:
        logger.warning(
            "Unknown or expired state at callback: state=%s cookie_present=%s",
            _mask_state(state or ""),
            bool(session_id),
        )
        # Without a stored return_url we can't safely redirect; return explicit JSON error
        return JSONResponse(
            status_code=400,
            content={
                "detail": "Unknown or expired state; cannot resolve return_url",
                "hint": "Restart the connection from the Connect page.",
            },
        )

    saved_return = state_payload.get("return_url") if isinstance(state_payload, dict) else None
    if not _is_absolute_url(saved_return):
        # Fallback safety: if return_url missing or invalid, emit JSON error
        return JSONResponse(
            status_code=400,
            content={"detail": "Saved return_url missing or invalid. Restart the connection."},
        )

    # Validate session and state alignment
    if not sess or not sess.state or sess.state != state or not sess.code_verifier:
        logger.warning(
            "Session/state mismatch: cookie_present=%s sess_has_state=%s sess_state_matches=%s code_verifier_len=%s",
            bool(session_id),
            bool(sess and sess.state),
            bool(sess and sess.state == state),
            (len(sess.code_verifier) if (sess and sess.code_verifier) else 0),
        )
        dest = f"{saved_return}?result=error&message={_encode_message('Invalid session or state; please retry connecting.')}"
        return RedirectResponse(dest, status_code=307)

    # Exchange code for tokens
    token_url = "https://auth.atlassian.com/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "code_verifier": sess.code_verifier,
    }
    if client_secret:
        payload["client_secret"] = client_secret

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            token_resp = await client.post(token_url, json=payload, headers={"Content-Type": "application/json"})
            if token_resp.status_code != 200:
                msg = f"Token exchange failed: {token_resp.text}"
                logger.error("Token exchange failed: status=%s body=%s", token_resp.status_code, token_resp.text)
                dest = f"{saved_return}?result=error&message={_encode_message(msg)}"
                return RedirectResponse(dest, status_code=307)
            token_json = token_resp.json()
    except Exception as ex:
        logger.exception("Network error during token exchange: %s", ex)
        dest = f"{saved_return}?result=error&message={_encode_message('Network error during token exchange')}"
        return RedirectResponse(dest, status_code=307)

    # Persist tokens in session
    save_tokens(session_id, token_json)

    # Success redirect; state already consumed for one-time use
    dest = f"{saved_return}?result=success"

    resp = RedirectResponse(dest, status_code=307)
    resp.set_cookie(
        key="sid",
        value=session_id or "",
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=60 * 60 * 24 * 14,
    )
    return resp


# PUBLIC_INTERFACE
@router.get(
    "/api/oauth/diagnostics",
    tags=["Auth"],
    summary="OAuth diagnostics (non-prod)",
    description="Return a safe summary of active OAuth states and TTL to aid debugging.",
)
async def oauth_diagnostics():
    """
    PUBLIC_INTERFACE
    Diagnostics endpoint to help trace state creation/expiration during development.
    Does not expose sensitive values.
    """
    diag = export_oauth_state_diagnostics()
    # Keep response shape stable and include backend type
    return JSONResponse(
        {
            "backend": diag.get("backend"),
            "approxActiveStates": diag.get("approxActiveStates", 0),
            "ttlSeconds": diag.get("ttlSeconds", get_state_ttl_seconds()),
        }
    )

# PUBLIC_INTERFACE
@router.get(
    "/api/oauth/state/debug",
    tags=["Auth"],
    summary="OAuth state debug (temporary)",
    description="DEBUG ONLY: Check if a given state exists and TTL remaining. Guarded by DEBUG_OAUTH=1.",
)
async def oauth_state_debug(state: Optional[str] = None):
    """
    PUBLIC_INTERFACE
    Debug endpoint to verify that a specific OAuth state exists and report TTL remaining.

    Guarded by environment variable DEBUG_OAUTH=1. Do not enable in production.
    """
    if os.getenv("DEBUG_OAUTH", "").strip() != "1":
        raise HTTPException(status_code=404, detail="Not found")
    if not state:
        raise HTTPException(status_code=400, detail="Missing state")

    # Try to non-destructively read the state by reusing export diagnostics or by attempting a get via consume simulation.
    # We cannot import a get_oauth_state here without changing public API; so do a light probe by consuming and then restoring is not safe.
    # Instead, document to use /api/oauth/diagnostics for counts and rely on callback logs for exact key issues.
    # For better fidelity, we include an existence check by calling consume then short-circuiting by returning existence only if absent.
    # Safer approach: attempt a consume in a 'shadow' flow is not possible without changing redis_client. So we return the masked key and hint.

    # Provide minimal safer info: state mask and configured TTL; actual existence is observable via callback behavior/logs.
    return JSONResponse(
        {
            "backend": "redis" if has_redis() else "memory",
            "stateMask": _mask_state(state),
            "ttlSeconds": get_state_ttl_seconds(),
            "note": "Existence cannot be probed without consuming in current API. Use callback logs and /api/oauth/diagnostics.",
        }
    )
