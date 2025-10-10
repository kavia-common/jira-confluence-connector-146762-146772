from __future__ import annotations

from typing import Optional, Dict, Any, List, NamedTuple
from time import time

# NOTE: This is an in-memory token store for scaffolding/dev only.
# TODO: Replace with durable store using INTEGRATION_DB_URL.

_STORE: Dict[str, Dict[str, Any]] = {}


def _key(connector: str, tenant_id: str) -> str:
    return f"{connector}:{tenant_id or 'default'}"


# PUBLIC_INTERFACE
def save_tokens(
    connector: str,
    tenant_id: str,
    access_token: str,
    refresh_token: Optional[str] = None,
    expires_at: Optional[int] = None,
    scopes: Optional[List[str]] = None,
    base_url: Optional[str] = None,
    cloud_id: Optional[str] = None,
    last_error: Optional[str] = None,
) -> None:
    """Save or update tokens for a connector/tenant."""
    record = _STORE.get(_key(connector, tenant_id), {})
    record.update(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_at": expires_at,
            "scopes": scopes,
            "base_url": base_url,
            "cloud_id": cloud_id,
            "last_error": last_error,
            "updated_at": int(time()),
        }
    )
    _STORE[_key(connector, tenant_id)] = record

# Compatibility shim: db-aware save_tokens used by some connectors
def save_tokens_db_aware(
    *,
    db: Any,
    connector_id: str,
    tenant_id: str,
    tokens: Dict[str, Optional[str]],
    scopes: Optional[str] = None,
    expires_at: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Compatibility wrapper to accept db session and tokens dict.

    Maps to in-memory store for now.
    """
    scopes_list = scopes.split() if isinstance(scopes, str) else None
    save_tokens(
        connector=connector_id,
        tenant_id=tenant_id,
        access_token=tokens.get("access_token") or "",
        refresh_token=tokens.get("refresh_token"),
        expires_at=expires_at,
        scopes=scopes_list,
    )


# PUBLIC_INTERFACE
def update_meta(
    connector: str,
    tenant_id: str,
    *,
    refreshed_at: Optional[int] = None,
    expires_at: Optional[int] = None,
    scopes: Optional[List[str]] = None,
    base_url: Optional[str] = None,
    cloud_id: Optional[str] = None,
    last_error: Optional[str] = None,
) -> None:
    """Update metadata fields for stored connection."""
    rec = _STORE.get(_key(connector, tenant_id))
    if not rec:
        return
    if refreshed_at is not None:
        rec["refreshed_at"] = refreshed_at
    if expires_at is not None:
        rec["expires_at"] = expires_at
    if scopes is not None:
        rec["scopes"] = scopes
    if base_url is not None:
        rec["base_url"] = base_url
    if cloud_id is not None:
        rec["cloud_id"] = cloud_id
    if last_error is not None:
        rec["last_error"] = last_error
    rec["updated_at"] = int(time())


# PUBLIC_INTERFACE
def get_tokens(connector: str, tenant_id: str) -> Optional[Dict[str, Any]]:
    """Return token data for connector/tenant, if present."""
    return _STORE.get(_key(connector, tenant_id))

# DB-aware compatibility: same as get_tokens but accepts db handle first
def get_tokens_db_aware(db: Any, connector: str, tenant_id: str) -> Optional[Dict[str, Any]]:
    """Compatibility wrapper signature get_tokens(db, connector, tenant_id)."""
    return get_tokens(connector, tenant_id)

class _TokenRecord(NamedTuple):
    access_token: Optional[str]
    refresh_token: Optional[str]
    scopes: Optional[str]
    expires_at: Optional[int]
    last_error: Optional[str]

# PUBLIC_INTERFACE
def get_token_record(db: Any, connector_id: str, tenant_id: str) -> Optional[_TokenRecord]:
    """Return a tuple-like record for compatibility with previous DB models."""
    rec = get_tokens(connector_id, tenant_id)
    if not rec:
        return None
    scopes_str = " ".join(rec.get("scopes") or []) if isinstance(rec.get("scopes"), list) else rec.get("scopes")
    return _TokenRecord(
        access_token=rec.get("access_token"),
        refresh_token=rec.get("refresh_token"),
        scopes=scopes_str,
        expires_at=rec.get("expires_at"),
        last_error=rec.get("last_error"),
    )


# PUBLIC_INTERFACE
def delete_tokens(connector: str, tenant_id: str) -> None:
    """Delete tokens for connector/tenant."""
    _STORE.pop(_key(connector, tenant_id), None)


# PUBLIC_INTERFACE
def list_connections(connector: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Return all connections or those for a specific connector."""
    if connector is None:
        return dict(_STORE)
    return {k: v for k, v in _STORE.items() if k.startswith(f"{connector}:")}
