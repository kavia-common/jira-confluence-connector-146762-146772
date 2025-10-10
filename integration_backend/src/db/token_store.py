from __future__ import annotations

from typing import Optional, Dict, Any, List
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
