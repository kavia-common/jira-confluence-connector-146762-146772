"""
Aligned OAuth endpoints for Atlassian with return_url handling.

This router adds:
- GET /api/oauth/atlassian/login: Accepts ?return_url=<absolute URL>, creates a random state,
  persists state->return_url mapping, and redirects (307) to Atlassian authorize URL.
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
from fastapi.responses import RedirectResponse

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

logger = logging.getLogger("oauth.return")

router = APIRouter()

# Simple in-memory state->return_url mapping (demo only)
_STATE_RETURN_URL_STORE: dict[str, str] = {}


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
        # Provide constructed expectation if backend_base is present
        hint = f"{(backend_base.rstrip('/') + '/api/oauth/atlassian/callback') if backend_base else 'BACKEND_PUBLIC_BASE_URL + /api/oauth/atlassian/callback'}"
        raise HTTPException(
            status_code=500,
            detail=f"Missing redirect_uri. Set BACKEND_PUBLIC_BASE_URL so redirect_uri resolves to {hint}, or set ATLASSIAN_REDIRECT_URI explicitly.",
        )
    if missing:
        raise HTTPException(status_code=500, detail=f"Missing environment variables: {', '.join(missing)}")

    if not _is_absolute_url(return_url):
        raise HTTPException(status_code=400, detail="Invalid or missing return_url; must be absolute (http/https).")

    # PKCE and state
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    csrf_state = generate_state()

    # Persist session data and state mapping
    existing_sid = request.cookies.get("sid")
    session_id = get_or_create_session_id(existing_sid)
    save_session(session_id, SessionData(state=csrf_state, code_verifier=code_verifier, token_set=None))
    _STATE_RETURN_URL_STORE[csrf_state] = return_url  # Demo persistence

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

    logger.info("Starting OAuth: sid set, state mapped; redirecting to Atlassian authorize")
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

    session_id = request.cookies.get("sid")
    sess = get_session(session_id) if session_id else None

    saved_return = _STATE_RETURN_URL_STORE.get(state)
    if not saved_return or not _is_absolute_url(saved_return):
        # Fallback: if no mapping available, avoid leaking; return an error JSON would be possible, but align to redirect pattern.
        raise HTTPException(status_code=400, detail="Unknown or expired state; cannot resolve return_url")

    # Validate state matches session to mitigate CSRF
    if not sess or not sess.state or sess.state != state or not sess.code_verifier:
        # redirect back to saved_return with error
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
                dest = f"{saved_return}?result=error&message={_encode_message(msg)}"
                return RedirectResponse(dest, status_code=307)
            token_json = token_resp.json()
    except Exception:
        dest = f"{saved_return}?result=error&message={_encode_message('Network error during token exchange')}"
        return RedirectResponse(dest, status_code=307)

    # Persist tokens in session
    save_tokens(session_id, token_json)

    # Success redirect
    dest = f"{saved_return}?result=success"
    # Cleanup: one-time use state mapping
    try:
        _STATE_RETURN_URL_STORE.pop(state, None)
    except Exception:
        pass

    resp = RedirectResponse(dest, status_code=307)
    # Ensure cookie persists
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
