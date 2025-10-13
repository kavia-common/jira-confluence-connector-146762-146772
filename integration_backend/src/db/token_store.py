from __future__ import annotations

"""
Thread-safe in-memory token store for connector tokens.

This module provides both:
- A simple TokenStore class used by some routers for CRUD access
- Functional helpers (save_tokens, get_tokens, get_token_record) expected by JiraConnector

No secrets are persisted to disk. This is suitable for previews and tests. For production,
replace with a persistent implementation (e.g., database).
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any
import threading
import time

# In-memory token storage keyed by tenant_id -> provider_id -> record dict
_STORE: Dict[str, Dict[str, Dict[str, Any]]] = {}
_LOCK = threading.Lock()


@dataclass
class TokenRecord:
    """Lightweight view of a stored token record."""
    connector_id: str
    tenant_id: str
    scopes: Optional[str] = None   # stored as space-separated string
    expires_at: Optional[int] = None
    last_error: Optional[str] = None


# PUBLIC_INTERFACE
def save_tokens(
    db: Any,  # unused, for compatibility with call sites
    connector_id: str,
    tenant_id: str,
    tokens: Dict[str, Any],
    scopes: Optional[str] = None,
    expires_at: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
    encrypted: bool = False,
) -> None:
    """Save or update tokens for a tenant+connector.

    Arguments:
    - db: unused placeholder to keep API parity with a DB-backed implementation
    - connector_id: provider name, e.g., 'jira'
    - tenant_id: tenant key/id
    - tokens: dict containing 'access_token' and optionally 'refresh_token'
    - scopes: optional space-separated scope string
    - expires_at: optional epoch seconds for access token expiry
    - metadata: optional dict with additional details (e.g., site selection)
    - encrypted: unused flag for compatibility
    """
    with _LOCK:
        _STORE.setdefault(tenant_id, {})
        rec = _STORE[tenant_id].get(connector_id) or {}
        rec["access_token"] = tokens.get("access_token")
        rec["refresh_token"] = tokens.get("refresh_token")
        rec["expires_at"] = expires_at
        # Store scopes as space-separated string for compatibility with JiraConnector
        rec["scopes"] = scopes
        rec["refreshed_at"] = int(time.time())
        # retain metadata in a structured way
        if metadata is not None:
            rec["metadata"] = metadata
        # last_error may be updated by callers on failures
        rec.setdefault("last_error", None)
        _STORE[tenant_id][connector_id] = rec


# PUBLIC_INTERFACE
def get_tokens(
    db: Any,  # unused
    connector_id: str,
    tenant_id: str,
) -> Optional[Dict[str, Any]]:
    """Return token dict for a tenant+connector or None if not stored."""
    with _LOCK:
        rec = (_STORE.get(tenant_id) or {}).get(connector_id)
        if not rec:
            return None
        return {
            "access_token": rec.get("access_token"),
            "refresh_token": rec.get("refresh_token"),
            "expires_at": rec.get("expires_at"),
            "scopes": rec.get("scopes"),
            "refreshed_at": rec.get("refreshed_at"),
            "metadata": rec.get("metadata"),
        }


# PUBLIC_INTERFACE
def get_token_record(
    db: Any,  # unused
    connector_id: str,
    tenant_id: str,
) -> Optional[TokenRecord]:
    """Return a TokenRecord view for a tenant+connector or None."""
    with _LOCK:
        rec = (_STORE.get(tenant_id) or {}).get(connector_id)
        if not rec:
            return None
        return TokenRecord(
            connector_id=connector_id,
            tenant_id=tenant_id,
            scopes=rec.get("scopes"),
            expires_at=rec.get("expires_at"),
            last_error=rec.get("last_error"),
        )


class TokenStore:
    """Simple thread-safe token store keyed by tenant and provider."""

    def get_token(self, tenant_id: str, provider: str) -> Optional[Dict[str, Any]]:
        with _LOCK:
            # Return a shallow copy to avoid external mutation
            rec = (_STORE.get(tenant_id) or {}).get(provider)
            return dict(rec) if rec else None

    def save_token(self, tenant_id: str, provider: str, record: Dict[str, Any]) -> None:
        with _LOCK:
            _STORE.setdefault(tenant_id, {})
            record = dict(record)
            # Ensure fields for status
            record.setdefault("refreshed_at", int(time.time()))
            # Normalize scopes: accept list[str] or str; store list for router-friendly shape
            scopes = record.get("scopes")
            if isinstance(scopes, list):
                record["scopes"] = [str(s) for s in scopes]
            elif isinstance(scopes, str):
                # Keep as str for compatibility with JiraConnector, but also stash list form
                record["scopes_list"] = [s for s in scopes.split() if s]
            _STORE[tenant_id][provider] = record

    def delete_token(self, tenant_id: str, provider: str) -> None:
        with _LOCK:
            if tenant_id in _STORE and provider in _STORE[tenant_id]:
                del _STORE[tenant_id][provider]
