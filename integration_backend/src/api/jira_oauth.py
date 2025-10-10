from __future__ import annotations

import json
import os
import secrets
import hmac
import hashlib
from typing import Optional, Dict, Any

from fastapi import APIRouter, Request, Query, status, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse

from src.api.schemas import OAuthAuthorizeURL
from src.api.oauth_config import (
    get_jira_oauth_config,
    build_atlassian_authorize_url,
    get_frontend_base_url_default,
)
from src.connectors.jira.impl import JiraConnector

# PUBLIC_INTERFACE
def _get_state_secret() -> str:
    """Return secret used for HMAC signing of OAuth state cookie."""
    return (
        os.getenv("STATE_SIGNING_SECRET")
        or os.getenv("CSRF_SECRET")
        or os.getenv("APP_SECRET_KEY")
        or os.getenv("SECRET_KEY")
        or "dev-insecure-secret"
    )

# PUBLIC_INTERFACE
def _sign_state(raw: str) -> str:
    """Sign a state value with HMAC-SHA256 and return raw.signature format."""
    mac = hmac.new(_get_state_secret().encode("utf-8"), msg=raw.encode("utf-8"), digestmod=hashlib.sha256)
    return f"{raw}.{mac.hexdigest()}"

# PUBLIC_INTERFACE
def _verify_signed_state(signed: str) -> bool:
    """Verify that the signed state matches its HMAC."""
    if not signed or "." not in signed:
        return False
    raw, sig = signed.rsplit(".", 1)
    mac = hmac.new(_get_state_secret().encode("utf-8"), msg=raw.encode("utf-8"), digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), sig)

# These names mirror Confluence router for consistency
_STATE_COOKIE_NAME = os.getenv("JIRA_STATE_COOKIE_NAME", "jira_oauth_state")
_STATE_COOKIE_TTL = int(os.getenv("JIRA_STATE_COOKIE_TTL_SEC", "600"))

router = APIRouter(tags=["Auth"])

# PUBLIC_INTERFACE
@router.get(
    "/auth/jira/login",
    summary="Start Jira OAuth flow",
    description="Generates Atlassian authorize URL with proper state and returns it as JSON by default. "
                "If redirect=true is passed, responds with a 307 redirect to Atlassian.",
    response_model=OAuthAuthorizeURL,
    responses={302: {"description": "Redirect to Atlassian authorize URL"}},
)
def jira_oauth_login(
    request: Request,
    return_url: Optional[str] = Query(None, description="Optional frontend URL to return to after auth success."),
    state: Optional[str] = Query(None, description="Optional client-provided opaque state to echo inside compound state."),
    scopes: Optional[str] = Query(None, description="Override default scopes."),
    redirect: Optional[bool] = Query(False, description="If true, send 307 redirect to authorize URL."),
):
    """
    PUBLIC_INTERFACE
    Jira OAuth login initializer.

    - Generates a signed state stored in an HttpOnly cookie and embeds it in a JSON 'state' sent to Atlassian.
    - The embedded state is a JSON object with fields: { csrf: <signed>, return_url?: <url>, tenant_id: "default", client?: <opaque> }.
    - Returns JSON { url } by default for SPA navigation, or 307 redirect when redirect=true.

    Returns:
    - JSON with 'url' or 307 RedirectResponse.
    """
    cfg = get_jira_oauth_config()
    client_id = (cfg.get("client_id") or "").strip()
    redirect_uri = (cfg.get("redirect_uri") or "").strip()

    if not client_id or not redirect_uri:
        raise HTTPException(status_code=400, detail="Jira OAuth is not configured (missing client_id/redirect_uri).")

    # Backend CSRF/state cookie
    raw_csrf = secrets.token_urlsafe(24)
    signed_csrf = _sign_state(raw_csrf)

    # Build compound JSON state that will be round-tripped via Atlassian
    compound: Dict[str, Any] = {"csrf": signed_csrf, "tenant_id": "default"}
    if state:
        compound["client"] = state
    if return_url:
        compound["return_url"] = return_url
    state_json = json.dumps(compound, separators=(",", ":"))

    # Default scopes if not provided
    effective_scopes = scopes or "read:jira-work read:jira-user offline_access"
    authorize_url = build_atlassian_authorize_url(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scopes=effective_scopes,
        state=state_json,
    )

    if redirect:
        resp = RedirectResponse(url=authorize_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
        resp.headers["Cache-Control"] = "no-store"
        # Set cookie to be sent on cross-site redirect back from Atlassian:
        # SameSite=None; Secure is required for third-party flows.
        resp.set_cookie(
            key=_STATE_COOKIE_NAME,
            value=signed_csrf,
            max_age=_STATE_COOKIE_TTL,
            httponly=True,
            secure=True,
            samesite="none",
            path="/",
        )
        return resp

    payload = {"url": authorize_url}
    resp = JSONResponse(status_code=200, content=payload)
    # SameSite=None; Secure to ensure browser sends cookie on Atlassian -> backend redirect
    resp.set_cookie(
        key=_STATE_COOKIE_NAME,
        value=signed_csrf,
        max_age=_STATE_COOKIE_TTL,
        httponly=True,
        secure=True,
        samesite="none",
        path="/",
    )
    return resp

# PUBLIC_INTERFACE
@router.get(
    "/auth/jira/callback",
    summary="Jira OAuth 2.0 callback",
    description="Validates state via signed cookie, exchanges code for tokens, persists, and redirects back to frontend return URL if supplied, or to /login as a safe default.",
    responses={
        302: {"description": "Redirect back to frontend return URL or /login"},
        400: {"description": "Missing code or config"},
        422: {"description": "Missing/invalid state"},
    },
)
def jira_oauth_callback(
    request: Request,
    code: Optional[str] = Query(None, description="Authorization code returned by Atlassian."),
    state: Optional[str] = Query(None, description="State returned by Atlassian."),
):
    """
    PUBLIC_INTERFACE
    Validate state, exchange code for tokens using JiraConnector, and redirect to frontend.

    Behavior:
    - Require `state`, parse JSON, extract 'csrf' and compare to signed cookie.
    - Require `code`.
    - On success, perform token exchange via JiraConnector and then redirect user to provided return_url if present,
      otherwise to FRONTEND_URL/login (keeping UX consistent).
    """
    if not state:
        raise HTTPException(status_code=422, detail="Missing state")

    cookie_state = request.cookies.get(_STATE_COOKIE_NAME)
    # Parse compound state JSON
    csrf_from_state: Optional[str] = None
    return_url: Optional[str] = None
    try:
        parsed = json.loads(state)
        if isinstance(parsed, dict):
            csrf_from_state = parsed.get("csrf") if isinstance(parsed.get("csrf"), str) else None
            ru = parsed.get("return_url")
            if isinstance(ru, str) and ru.strip():
                return_url = ru.strip()
    except Exception:
        csrf_from_state = None

    if not csrf_from_state:
        raise HTTPException(status_code=422, detail="Invalid state format")

    if not cookie_state:
        raise HTTPException(status_code=422, detail="Missing state cookie")
    if not _verify_signed_state(csrf_from_state):
        raise HTTPException(status_code=422, detail="Invalid state signature")
    if not hmac.compare_digest(str(cookie_state), str(csrf_from_state)):
        raise HTTPException(status_code=422, detail="State mismatch")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code")

    # Exchange code for tokens and persist via JiraConnector
    connector = JiraConnector().with_db(None)  # JiraConnector handles db via internal helpers if needed
    try:
        # Tenant is default unless provided in state
        tenant_id = "default"
        try:
            j = json.loads(state)
            if isinstance(j, dict) and j.get("tenant_id"):
                tenant_id = str(j.get("tenant_id"))
        except Exception:
            pass
        connector.oauth_callback(code=code, tenant_id=tenant_id, state=state)
    except HTTPException:
        # Redirect with error hint to login page
        base = get_frontend_base_url_default() or os.getenv("NEXT_PUBLIC_APP_FRONTEND_URL") or ""
        url = f"{base.rstrip('/')}/login?error=oauth_exchange_failed"
        return RedirectResponse(url=url, status_code=302)

    # Success: choose redirect target
    target = return_url
    if not target:
        base = get_frontend_base_url_default() or os.getenv("NEXT_PUBLIC_APP_FRONTEND_URL") or ""
        target = f"{base.rstrip('/')}/login?connected=jira"

    return RedirectResponse(url=target, status_code=302)
