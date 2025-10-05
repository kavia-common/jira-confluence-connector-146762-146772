"""
PKCE utilities and simple in-memory session store for Atlassian OAuth 2.0 (3LO) flows.

Implements:
- PKCE code_verifier and code_challenge generation (RFC 7636)
- CSRF state generation
- Simple in-memory store keyed by a session_id cookie to keep PKCE verifier/state and tokens
  NOTE: This is demo-only; for production, migrate to Redis or a DB.

Environment-driven configuration is handled by oauth_settings.py.
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from typing import Dict, Optional


def _b64url_nopad(data: bytes) -> str:
    """Base64 URL-safe encoding without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


# PUBLIC_INTERFACE
def generate_code_verifier(length: int = 64) -> str:
    """Generate a high-entropy PKCE code_verifier (43-128 chars)."""
    if length < 43 or length > 128:
        length = 64
    # Use URL-safe characters, increase entropy by using secrets.token_urlsafe then trim
    # token_urlsafe returns ~1.3 * n length; we overshoot and slice.
    verifier = secrets.token_urlsafe(length + 10)[:length]
    return verifier


# PUBLIC_INTERFACE
def generate_code_challenge(code_verifier: str) -> str:
    """Compute S256 code_challenge from code_verifier per RFC 7636."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return _b64url_nopad(digest)


# PUBLIC_INTERFACE
def generate_state(length: int = 32) -> str:
    """Generate random state string for CSRF mitigation."""
    return _b64url_nopad(os.urandom(length))


@dataclass
class TokenSet:
    access_token: str
    refresh_token: Optional[str]
    token_type: str
    scope: Optional[str]
    expires_in: Optional[int]
    obtained_at: int  # epoch seconds

    # PUBLIC_INTERFACE
    def is_expired(self) -> bool:
        """Determine if the access token is expired, with a small safety window."""
        if not self.expires_in:
            return False
        return (self.obtained_at + max(0, int(self.expires_in) - 30)) <= int(time.time())


@dataclass
class SessionData:
    state: str
    code_verifier: str
    token_set: Optional[TokenSet] = None


# In-memory store: session_id -> SessionData
_SESSION_STORE: Dict[str, SessionData] = {}


# PUBLIC_INTERFACE
def get_or_create_session_id(existing: Optional[str]) -> str:
    """Return a session_id; if not present, create a new secure random one."""
    if existing and existing in _SESSION_STORE:
        return existing
    # 32 bytes -> 43 char urlsafe string
    sid = _b64url_nopad(secrets.token_bytes(32))
    return sid


# PUBLIC_INTERFACE
def save_session(session_id: str, session: SessionData) -> None:
    """Save session data."""
    _SESSION_STORE[session_id] = session


# PUBLIC_INTERFACE
def get_session(session_id: str) -> Optional[SessionData]:
    """Load session data by id."""
    return _SESSION_STORE.get(session_id)


# PUBLIC_INTERFACE
def save_tokens(session_id: str, token_json: dict) -> TokenSet:
    """Persist tokens to session."""
    token = TokenSet(
        access_token=token_json.get("access_token"),
        refresh_token=token_json.get("refresh_token"),
        token_type=token_json.get("token_type", "Bearer"),
        scope=token_json.get("scope"),
        expires_in=token_json.get("expires_in"),
        obtained_at=int(time.time()),
    )
    sess = _SESSION_STORE.get(session_id)
    if not sess:
        # if no session exists, create minimal one (no state/verifier)
        sess = SessionData(state="", code_verifier="", token_set=token)
    else:
        sess.token_set = token
    _SESSION_STORE[session_id] = sess
    return token


# PUBLIC_INTERFACE
def export_session_debug(session_id: str) -> dict:
    """Export a safe view of the session for debugging (avoid exposing tokens in logs)."""
    sess = _SESSION_STORE.get(session_id)
    if not sess:
        return {}
    data = {
        "has_token": bool(sess.token_set and sess.token_set.access_token),
        "state": "***" if sess.state else "",
        "code_verifier_len": len(sess.code_verifier) if sess.code_verifier else 0,
    }
    return data
