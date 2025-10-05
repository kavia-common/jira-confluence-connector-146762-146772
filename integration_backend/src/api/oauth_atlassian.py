from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
from typing import Optional
import os
import urllib.parse
import logging

# Ensure environment variables are available
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    # dotenv is optional; continue if not available
    pass

router = APIRouter()

ATLASSIAN_AUTHORIZE_URL = "https://auth.atlassian.com/authorize"
DEFAULT_SCOPES = [
    "read:jira-work",
    "read:jira-user",
    "write:jira-work",
    "offline_access",
    "read:confluence-content.all",
    "read:confluence-content.summary",
]

def _get_required_env():
    client_id = os.getenv("ATLASSIAN_CLIENT_ID")
    redirect_uri = os.getenv("ATLASSIAN_REDIRECT_URI")
    return client_id, redirect_uri

# PUBLIC_INTERFACE
@router.get("/api/oauth/start", tags=["Auth"], summary="OAuth start shim", include_in_schema=True)
async def oauth_start(request: Request, return_url: Optional[str] = None):
    """
    Redirect shim for legacy/unstable clients.
    Accepts optional return_url, forwards as 'redirect' to /api/oauth/atlassian/login via 307.
    Returns:
        307 Temporary Redirect to /api/oauth/atlassian/login?redirect=<return_url>
    """
    backend_base = str(request.base_url).rstrip("/")
    target = f"{backend_base}/api/oauth/atlassian/login"
    if return_url:
        qs = urllib.parse.urlencode({"redirect": return_url})
        target = f"{target}?{qs}"
    return RedirectResponse(url=target, status_code=307)

# PUBLIC_INTERFACE
@router.get("/api/oauth/atlassian/login", tags=["Auth"], summary="Start Atlassian OAuth 2.0 (3LO)", include_in_schema=True)
async def atlassian_login(redirect: Optional[str] = None, state: Optional[str] = None, scope: Optional[str] = None):
    """
    Constructs a redirect to Atlassian authorize endpoint.
    Query params:
      - redirect: optional URL to send user to after our callback finishes (embedded in state)
      - state: optional custom state; if provided, we still embed redirect to preserve it
      - scope: optional scope override (space-delimited). Defaults to DEFAULT_SCOPES.
    Returns:
      302 Found redirect to Atlassian authorize URL.
    """
    client_id, redirect_uri = _get_required_env()
    if not client_id or not redirect_uri:
        logging.error("Missing ATLASSIAN_CLIENT_ID or ATLASSIAN_REDIRECT_URI environment variables.")
        return JSONResponse(
            status_code=500,
            content={
                "error": "server_misconfigured",
                "message": "Missing ATLASSIAN_CLIENT_ID or ATLASSIAN_REDIRECT_URI. Please set backend environment variables."
            },
        )

    scopes = scope.split(" ") if scope else DEFAULT_SCOPES
    scope_str = " ".join(scopes)

    # Minimal state: embed provided state and redirect within URL-encoded JSON-like string
    # This is kept simple; a robust app would sign and store state server-side.
    state_payload = {"redirect": redirect} if redirect else {}
    if state:
        state_payload["client_state"] = state
    encoded_state = urllib.parse.quote_plus(str(state_payload))

    params = {
        "audience": "api.atlassian.com",
        "client_id": client_id,
        "scope": scope_str,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "prompt": "consent",
        "state": encoded_state,
    }
    authorize_url = f"{ATLASSIAN_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"
    return RedirectResponse(url=authorize_url, status_code=302)
