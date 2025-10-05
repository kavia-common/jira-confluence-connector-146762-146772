"""
FastAPI routes for Atlassian OAuth 2.0 (3LO) with PKCE.

Provides:
- GET /api/oauth/atlassian/login -> generates state + PKCE, stores in session cookie, redirects to Atlassian authorize
- GET /api/oauth/callback/atlassian -> validates state, exchanges code for tokens, stores tokens, redirects to frontend
- POST /api/oauth/atlassian/refresh -> uses refresh_token to obtain new access_token
- GET /api/atlassian/resources -> calls accessible-resources with access_token to verify and list Cloud IDs

Security:
- Uses httpOnly, Secure, SameSite=Lax cookie 'sid' as session key
- In-memory session store (demo). TODO: replace with Redis.
"""

from __future__ import annotations

import urllib.parse
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse

from .oauth_pkce import (
    generate_code_verifier,
    generate_code_challenge,
    generate_state,
    get_or_create_session_id,
    save_session,
    get_session,
    save_tokens,
)
from .oauth_pkce import SessionData
from .oauth_settings import get_atlassian_oauth_config, get_default_scopes

router = APIRouter()


def _set_session_cookie(resp: Response, session_id: str) -> None:
    # For dev, Secure=True may be ignored if not HTTPS; leave as True to align with best practice.
    resp.set_cookie(
        key="sid",
        value=session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
        max_age=60 * 60 * 24 * 14,  # 14 days
    )


# PUBLIC_INTERFACE
@router.get(
    "/api/oauth/atlassian/login",
    tags=["Auth"],
    summary="Start Atlassian OAuth 2.0 (3LO) with PKCE",
    description="Generates PKCE parameters and redirects to Atlassian authorization endpoint.",
)
async def atlassian_login(request: Request, state: Optional[str] = None, scope: Optional[str] = None):
    """
    Initiate Atlassian OAuth with PKCE.

    Query:
        state: optional caller-provided state; otherwise generated server-side.
        scope: optional space-separated scopes; falls back to env defaults.

    Returns:
        302 redirect to Atlassian authorize endpoint with PKCE params.
    """
    cfg = get_atlassian_oauth_config()
    client_id = cfg.get("client_id")
    redirect_uri = cfg.get("redirect_uri")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Atlassian OAuth not configured. Set ATLASSIAN_CLIENT_ID and ATLASSIAN_REDIRECT_URI.")

    # PKCE + state
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    csrf_state = state or generate_state()

    # Persist in in-memory session
    existing_sid = request.cookies.get("sid")
    session_id = get_or_create_session_id(existing_sid)
    save_session(session_id, SessionData(state=csrf_state, code_verifier=code_verifier, token_set=None))

    # Scopes
    scopes = scope or cfg.get("scopes") or get_default_scopes()

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
    resp = RedirectResponse(url)
    _set_session_cookie(resp, session_id)
    return resp


# PUBLIC_INTERFACE
@router.get(
    "/api/oauth/callback/atlassian",
    tags=["Auth"],
    summary="Atlassian OAuth callback",
    description="Handles redirect from Atlassian, validates state, exchanges code for tokens using PKCE, and stores tokens in session.",
)
async def atlassian_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None):
    """
    Complete Atlassian OAuth with PKCE.

    On success:
        - tokens are saved server-side under session
        - user is redirected to frontend: /connected or configurable page
    """
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    cfg = get_atlassian_oauth_config()
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret") or None  # optional
    redirect_uri = cfg.get("redirect_uri")
    frontend_url = cfg.get("frontend_url") or "/connected"

    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Atlassian OAuth not configured properly.")

    session_id = request.cookies.get("sid")
    sess = get_session(session_id) if session_id else None
    if not sess or not sess.state or not sess.code_verifier:
        raise HTTPException(status_code=400, detail="Session not found or expired. Please restart login.")

    # Validate state
    if not state or state != sess.state:
        raise HTTPException(status_code=400, detail="Invalid state. Please retry login.")

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

    async with httpx.AsyncClient(timeout=30.0) as client:
        token_resp = await client.post(token_url, json=payload, headers={"Content-Type": "application/json"})
        if token_resp.status_code != 200:
            # Log details in error body for easier debugging
            raise HTTPException(status_code=token_resp.status_code, detail=f"Token exchange failed: {token_resp.text}")
        token_json = token_resp.json()

    # Persist tokens in session
    save_tokens(session_id, token_json)

    # Redirect to frontend success page
    # Allow appending query marks for simple verification
    params = {"provider": "atlassian", "status": "success"}
    dest = f"{(frontend_url or '/').rstrip('/')}"
    # If frontend_url already includes query we append with '&'
    if "?" in dest:
        dest = f"{dest}&provider=atlassian&status=success"
    else:
        dest = f"{dest}?{urllib.parse.urlencode(params)}"

    resp = RedirectResponse(dest)
    # Ensure cookie persists
    _set_session_cookie(resp, session_id)
    return resp


# PUBLIC_INTERFACE
@router.post(
    "/api/oauth/atlassian/refresh",
    tags=["Auth"],
    summary="Refresh Atlassian access token",
    description="Uses refresh_token stored in session to get a new access_token.",
)
async def atlassian_refresh(request: Request):
    """
    Refresh the access token using the stored refresh_token.

    Returns:
        JSON with new expiry info (no tokens returned to client for safety).
    """
    session_id = request.cookies.get("sid")
    sess = get_session(session_id) if session_id else None
    if not sess or not sess.token_set or not sess.token_set.refresh_token:
        raise HTTPException(status_code=400, detail="No refresh token found. Reconnect.")

    cfg = get_atlassian_oauth_config()
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret") or None
    if not client_id:
        raise HTTPException(status_code=500, detail="Missing ATLASSIAN_CLIENT_ID")

    token_url = "https://auth.atlassian.com/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": sess.token_set.refresh_token,
    }
    if client_secret:
        payload["client_secret"] = client_secret

    async with httpx.AsyncClient(timeout=30.0) as client:
        token_resp = await client.post(token_url, json=payload, headers={"Content-Type": "application/json"})
        if token_resp.status_code != 200:
            raise HTTPException(status_code=token_resp.status_code, detail=f"Refresh failed: {token_resp.text}")
        token_json = token_resp.json()

    save_tokens(session_id, token_json)
    # Return a safe summary (not the raw tokens)
    return JSONResponse(
        {
            "status": "success",
            "message": "Token refreshed",
            "data": {
                "expires_in": token_json.get("expires_in"),
                "scope": token_json.get("scope"),
                "token_type": token_json.get("token_type"),
            },
        }
    )


# PUBLIC_INTERFACE
@router.get(
    "/api/atlassian/resources",
    tags=["Auth"],
    summary="List Atlassian accessible resources",
    description="Calls Atlassian API to list accessible cloud resources using the session access_token.",
)
async def list_accessible_resources(request: Request):
    """
    Use the access_token to list accessible resources (cloud IDs).

    Returns:
        JSON list of accessible resources (safe to display).
    """
    session_id = request.cookies.get("sid")
    sess = get_session(session_id) if session_id else None
    if not sess or not sess.token_set or not sess.token_set.access_token:
        raise HTTPException(status_code=401, detail="Not authenticated. Start login flow.")

    url = "https://api.atlassian.com/oauth/token/accessible-resources"
    headers = {"Authorization": f"Bearer {sess.token_set.access_token}"}

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            raise HTTPException(status_code=resp.status_code, detail=f"Failed to fetch resources: {resp.text}")
        items = resp.json()

    return JSONResponse({"status": "success", "message": "ok", "data": items})
