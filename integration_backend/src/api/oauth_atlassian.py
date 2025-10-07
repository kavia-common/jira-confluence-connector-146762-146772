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

import logging

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
from .oauth_config import (
    get_jira_oauth_config,
    get_frontend_base_url_default,
)

router = APIRouter()

# PUBLIC_INTERFACE
@router.get(
    "/auth/jira",
    tags=["Auth"],
    summary="Get Jira OAuth authorization URL (JSON)",
    description="Returns JSON { url } with the Atlassian authorize URL constructed from environment configuration. Frontend should fetch this endpoint and redirect the browser to the returned url.",
    responses={
        200: {
            "description": "Successful Response",
            "content": {"application/json": {"example": {"url": "https://auth.atlassian.com/authorize?..."} }},
        },
        500: {"description": "Server error when OAuth is not configured"},
    },
)
async def jira_get_oauth_url(state: Optional[str] = None, scope: Optional[str] = None):
    """
    Return the Atlassian authorize URL for Jira OAuth 2.0 as JSON.

    Query:
        state: optional state string to be appended.
        scope: optional space-separated scopes (falls back to defaults in this handler).

    Returns:
        JSON object: {"url": "<authorize url>"}
    """
    cfg = get_jira_oauth_config()
    client_id = cfg.get("client_id")
    redirect_uri = cfg.get("redirect_uri")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Jira OAuth is not configured. Set environment variables.")

    default_scopes = [
        "read:jira-work",
        "read:jira-user",
        "offline_access",
    ]
    scopes = scope or " ".join(default_scopes)

    authorize_url = "https://auth.atlassian.com/authorize"
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

    url = f"{authorize_url}?{urllib.parse.urlencode(params)}"
    return JSONResponse({"url": url})

# PUBLIC_INTERFACE
@router.get(
    "/api/auth/jira/login",
    tags=["Auth"],
    summary="Alias: Start Jira OAuth (API-prefixed)",
    description="Compatibility alias that redirects to /auth/jira/login. Preserves state, scope, and return_url (as state embedding).",
)
async def jira_login_alias(request: Request, state: Optional[str] = None, scope: Optional[str] = None, return_url: Optional[str] = None):
    """
    Compatibility alias for clients expecting /api/auth/jira/login.
    Redirects to /auth/jira/login, preserving query params.
    """
    # Build destination URL preserving supported params
    params = {}
    if state:
        params["state"] = state
    if scope:
        params["scope"] = scope
    # Preserve return_url as state suffix for clients that rely on it
    # If both state and return_url present, append to state.
    if return_url:
        if "state" in params and params["state"]:
            params["state"] = f"{params['state']}|post_redirect={urllib.parse.quote_plus(return_url)}"
        else:
            params["state"] = f"post_redirect={urllib.parse.quote_plus(return_url)}"
    dest = "/auth/jira/login"
    if params:
        dest = f"{dest}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(dest, status_code=307)


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
async def atlassian_login(request: Request, state: Optional[str] = None, scope: Optional[str] = None, return_url: Optional[str] = None):
    """
    Initiate Atlassian OAuth with PKCE.

    Query:
        state: optional caller-provided state; otherwise generated server-side.
        scope: optional space-separated scopes; falls back to env defaults.
        redirect: optional absolute frontend URL to return to after callback; embedded in state as post_redirect.
                  Use the dedicated /api/oauth/atlassian/login?return_url=... flow if you prefer explicit return_url storage.

    Returns:
        302 redirect to Atlassian authorize endpoint with PKCE params.
    """
    logger = logging.getLogger("oauth.atlassian")
    cfg = get_atlassian_oauth_config()
    client_id = cfg.get("client_id")
    redirect_uri = cfg.get("redirect_uri")
    backend_base = cfg.get("backend_base_url")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Atlassian OAuth not configured. Set ATLASSIAN_CLIENT_ID and ATLASSIAN_REDIRECT_URI.")

    # Warn if request host is localhost but backend base is configured as cloud URL
    req_host = request.headers.get("host", "")
    if "localhost" in req_host.lower() and backend_base and "localhost" not in backend_base.lower():
        logger.warning(
            "Login requested via localhost host header while BACKEND_BASE_URL is cloud (%s). Proceeding with env-based redirect_uri.",
            backend_base,
        )

    # Optional UI redirect after successful callback, captured from query but not sent to Atlassian
    # Support both ?redirect= and ?return_url= as aliases.
    post_redirect = request.query_params.get("redirect") or return_url

    # PKCE + state
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    csrf_state = state or generate_state()

    # Persist in in-memory session
    existing_sid = request.cookies.get("sid")
    session_id = get_or_create_session_id(existing_sid)
    # Store state, verifier
    save_session(session_id, SessionData(state=csrf_state, code_verifier=code_verifier, token_set=None))

    # Embed post_redirect into state to preserve across round-trip. Ignore any attempt to override redirect_uri via query.
    embedded_state = csrf_state
    if post_redirect:
        embedded_state = f"{csrf_state}|post_redirect={urllib.parse.quote_plus(post_redirect)}"

    # Scopes
    scopes = scope or cfg.get("scopes") or get_default_scopes()

    # Build authorize URL using exact env redirect_uri (never overridden)
    authorize_url = "https://auth.atlassian.com/authorize"
    params = {
        "audience": "api.atlassian.com",
        "client_id": client_id,
        "scope": scopes,
        "redirect_uri": redirect_uri,
        "state": embedded_state,
        "response_type": "code",
        "prompt": "consent",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    url = f"{authorize_url}?{urllib.parse.urlencode(params)}"

    # Log key parts (no secrets)
    logger.info(
        "OAuth start: incoming host=%s path=%s query=%s",
        request.headers.get("host", ""),
        request.url.path,
        str(request.url.query),
    )
    logger.info(
        "Constructed Atlassian authorize URL with client_id=%s, redirect_uri=%s, scopes=%s, has_state=%s, redirecting_to_auth=%s",
        client_id[:4] + "..." if client_id else "",
        redirect_uri,
        scopes,
        bool(embedded_state),
        authorize_url,
    )

    # Determine if the client expects JSON (XHR/fetch) vs browser navigation
    accept = (request.headers.get("accept") or "").lower()
    xrw = (request.headers.get("x-requested-with") or "").lower()
    wants_json = ("application/json" in accept) or (xrw == "xmlhttprequest")

    if wants_json:
        resp = JSONResponse({"url": url})
        _set_session_cookie(resp, session_id)
        return resp

    resp = RedirectResponse(url, status_code=307)
    _set_session_cookie(resp, session_id)
    return resp

# PUBLIC_INTERFACE
@router.get(
    "/auth/jira/login",
    tags=["Auth"],
    summary="Start Jira OAuth 2.0 login (legacy shim)",
    description="Redirects the user to Atlassian authorization page using legacy non-PKCE Jira client configuration.",
)
async def jira_login_legacy(state: Optional[str] = None, scope: Optional[str] = None):
    """
    Legacy Jira OAuth 2.0 authorization flow using client_secret.
    This is kept for backward compatibility and mirrors the behavior in src/api/main.py,
    but declared here so it is available under any active FastAPI entrypoint.

    Returns:
        302 redirect to Atlassian authorization endpoint.
    """
    cfg = get_jira_oauth_config()
    client_id = cfg.get("client_id")
    redirect_uri = cfg.get("redirect_uri")
    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Jira OAuth is not configured. Set environment variables.")

    default_scopes = [
        "read:jira-work",
        "read:jira-user",
        "offline_access",
    ]
    scopes = scope or " ".join(default_scopes)

    authorize_url = "https://auth.atlassian.com/authorize"
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

    url = f"{authorize_url}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url)

# PUBLIC_INTERFACE
@router.get(
    "/api/oauth/start",
    tags=["Auth"],
    summary="OAuth start shim",
    description="Redirect shim for legacy clients. Redirects to /api/oauth/atlassian/login, preserving return_url as ?redirect=...",
)
async def oauth_start(request: Request):
    """
    Shim endpoint to support legacy clients that call /api/oauth/start.

    Query:
        redirect: optional post-auth UI target (preferred)
        return_url: optional alias for redirect for backward compatibility

    Returns:
        307 Temporary Redirect to /api/oauth/atlassian/login with redirect preserved.
    """
    # Normalize redirect
    redirect_param = request.query_params.get("redirect")
    return_url_param = request.query_params.get("return_url")
    final_redirect = redirect_param or return_url_param

    # Build destination preserving redirect if available
    dest = "/api/oauth/atlassian/login"
    if final_redirect:
        dest = f"{dest}?redirect={urllib.parse.quote_plus(final_redirect)}"

    # Use 307 to preserve method semantics even though this is GET
    response = RedirectResponse(dest, status_code=307)
    return response


# PUBLIC_INTERFACE
@router.get(
    "/routes",
    tags=["Health"],
    summary="List registered routes",
    description="Diagnostic endpoint: lists all registered routes and methods.",
)
async def list_routes(request: Request):
    """
    Return a list of registered routes and their methods for diagnostics.

    Returns:
        JSON list of objects: {path, methods, name}
    """
    app = request.app
    items = []
    for r in app.routes:
        try:
            path = getattr(r, "path", "")
            name = getattr(r, "name", "")
            methods = sorted(list(getattr(r, "methods", set()))) if hasattr(r, "methods") else []
            items.append({"path": path, "methods": methods, "name": name})
        except Exception:
            continue
    return JSONResponse(items)


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
        - user is redirected to FRONTEND_BASE_URL or an embedded post_redirect from the original state
    """
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    cfg = get_atlassian_oauth_config()
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret") or None  # optional
    redirect_uri = cfg.get("redirect_uri")
    frontend_base = cfg.get("frontend_url") or "/connected"

    if not client_id or not redirect_uri:
        raise HTTPException(status_code=500, detail="Atlassian OAuth not configured properly.")

    session_id = request.cookies.get("sid")
    sess = get_session(session_id) if session_id else None
    if not sess or not sess.state or not sess.code_verifier:
        raise HTTPException(status_code=400, detail="Session not found or expired. Please restart login.")

    # Validate state and optionally extract post_redirect that was embedded
    # Expected format: "<csrf_state>" or "<csrf_state>|post_redirect=<urlencoded>"
    if not state or not state.startswith(sess.state):
        raise HTTPException(status_code=400, detail="Invalid state. Please retry login.")
    post_redirect = None
    if "|post_redirect=" in state:
        try:
            post_redirect_enc = state.split("|post_redirect=", 1)[1]
            post_redirect = urllib.parse.unquote_plus(post_redirect_enc)
        except Exception:
            post_redirect = None

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

    # Redirect to frontend success page (prefer embedded post_redirect if provided)
    base_dest = post_redirect or frontend_base or "/"
    params = {"provider": "atlassian", "status": "success"}
    dest = f"{base_dest.rstrip('/')}"
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

# PUBLIC_INTERFACE
@router.get(
    "/auth/jira/callback",
    tags=["Auth"],
    summary="Jira OAuth 2.0 callback (legacy shim)",
    description="Handles Atlassian redirect for legacy non-PKCE flow, exchanges code for tokens (server-side), and redirects to frontend.",
)
async def jira_callback_legacy(request: Request, code: Optional[str] = None, state: Optional[str] = None):
    """
    Complete Jira OAuth 2.0 legacy flow (non-PKCE) for backward compatibility.
    Exchanges code for tokens and redirects back to the frontend base URL.
    For demo safety, tokens are not returned to client.

    Note: This legacy handler does not persist to DB. Prefer PKCE session-based flows.
    """
    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    cfg = get_jira_oauth_config()
    client_id = cfg.get("client_id")
    client_secret = cfg.get("client_secret")
    redirect_uri = cfg.get("redirect_uri")
    if not client_id or not client_secret or not redirect_uri:
        raise HTTPException(status_code=500, detail="Jira OAuth is not configured. Set environment variables.")

    token_url = "https://auth.atlassian.com/oauth/token"
    data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        token_resp = await client.post(token_url, json=data, headers={"Content-Type": "application/json"})
        if token_resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Token exchange failed: {token_resp.text}")
        _ = token_resp.json()  # Do not expose tokens; this is legacy shim only.

    # Redirect back to frontend; prefer configured FRONTEND_BASE_URL
    frontend = get_frontend_base_url_default() or "/"
    params = {
        "provider": "jira",
        "status": "success",
        "state": state or "",
    }
    redirect_to = f"{frontend.rstrip('/')}/oauth/callback?{urllib.parse.urlencode(params)}"
    return RedirectResponse(redirect_to)


# PUBLIC_INTERFACE
@router.get(
    "/api/config",
    tags=["Health"],
    summary="Effective configuration (base URLs and redirect URI)",
    description="Returns the effective public URLs and Atlassian redirect URI sourced from environment for diagnostics. Secrets are not included.",
    responses={200: {"description": "Successful Response"}},
)
async def get_effective_config():
    """
    Return the effective configuration for quick validation.

    Returns:
        JSON with backendBaseUrl, frontendBaseUrl, redirectUri and presence flags.
    """
    cfg = get_atlassian_oauth_config()
    client_id_present = bool(cfg.get("client_id"))
    redirect_present = bool(cfg.get("redirect_uri"))
    scopes_present = bool(cfg.get("scopes"))
    try:
        from .redis_client import has_redis, get_state_ttl_seconds  # type: ignore
        has_redis_flag = bool(has_redis())
        ttl_seconds = int(get_state_ttl_seconds())
    except Exception:
        has_redis_flag = False
        ttl_seconds = 600
    return JSONResponse(
        {
            "backendBaseUrl": cfg.get("backend_base_url") or "",
            "frontendBaseUrl": cfg.get("frontend_url") or "",
            "redirectUri": cfg.get("redirect_uri") or "",
            "hasClientId": client_id_present,
            "hasRedirectUri": redirect_present,
            "hasScopes": scopes_present,
            "hasRedis": has_redis_flag,
            "stateTtlSeconds": ttl_seconds,
        }
    )
