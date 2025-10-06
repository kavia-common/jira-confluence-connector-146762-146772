"""
Redis client utility with graceful fallback for OAuth state storage.

This module centralizes Redis connectivity and provides small helper functions
to store/retrieve/delete ephemeral OAuth state with TTL.

Env:
- REDIS_URL: connection string (e.g., redis://localhost:6379). If missing/empty, fallback to in-memory store.
- OAUTH_STATE_TTL_SECONDS: TTL for state entries. Defaults to 600 seconds.

Notes:
- Uses SETEX semantics when Redis is available.
- In-memory fallback is process-local and should be used only for development/testing.
"""

from __future__ import annotations

# Ensure .env is loaded
from src import startup  # noqa: F401

import json
import logging
import os
import threading
import time
from typing import Any, Dict, Optional, Tuple

try:
    import redis  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    redis = None  # type: ignore

_logger = logging.getLogger("redis.client")

# In-memory fallback store for state, guarded by a lock
# key -> (value_json_str, expires_at_epoch)
_MEMORY_STORE: Dict[str, Tuple[str, int]] = {}
_MEMORY_LOCK = threading.Lock()


def _get_ttl_seconds() -> int:
    """Resolve TTL seconds for OAuth state storage."""
    try:
        return int(os.getenv("OAUTH_STATE_TTL_SECONDS", "600"))
    except Exception:
        return 600


def _namespace_key(key: str) -> str:
    """Apply a namespaced prefix for keys."""
    return f"oauth:state:{key}"


def _prune_memory_store() -> None:
    """Remove expired entries from in-memory store."""
    now = int(time.time())
    with _MEMORY_LOCK:
        expired = [k for k, (_, exp) in _MEMORY_STORE.items() if exp <= now]
        for k in expired:
            _MEMORY_STORE.pop(k, None)


def _get_redis_client():
    """Get a Redis client instance if REDIS_URL is configured and redis lib is available; else None."""
    url = os.getenv("REDIS_URL", "").strip()
    if not url or redis is None:
        return None
    try:
        client = redis.from_url(url, decode_responses=True)
        # Do a light ping to validate connectivity
        client.ping()
        return client
    except Exception as e:
        _logger.warning("Failed to connect to Redis at REDIS_URL=%s: %s. Falling back to in-memory.", url, e)
        return None


# PUBLIC_INTERFACE
def has_redis() -> bool:
    """Return True if Redis is configured and reachable."""
    return _get_redis_client() is not None


# PUBLIC_INTERFACE
def get_state_ttl_seconds() -> int:
    """Return the configured TTL seconds used for OAuth state."""
    return _get_ttl_seconds()


# PUBLIC_INTERFACE
def save_oauth_state(state: str, payload: Dict[str, Any]) -> None:
    """Save OAuth state mapping to JSON payload with TTL.

    Payload expected keys:
      - return_url: str
      - code_verifier: str
    """
    ttl = _get_ttl_seconds()
    key = _namespace_key(state)
    data = json.dumps(payload)
    client = _get_redis_client()
    if client:
        # Use SETEX for TTL
        client.setex(key, ttl, data)
        return
    # Fallback to in-memory
    expires_at = int(time.time()) + ttl
    with _MEMORY_LOCK:
        _MEMORY_STORE[key] = (data, expires_at)


# PUBLIC_INTERFACE
def get_oauth_state(state: str) -> Optional[Dict[str, Any]]:
    """Get OAuth state payload without consuming it (non-destructive read)."""
    key = _namespace_key(state)
    client = _get_redis_client()
    if client:
        raw = client.get(key)
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None
    # Memory fallback
    _prune_memory_store()
    with _MEMORY_LOCK:
        raw_tuple = _MEMORY_STORE.get(key)
        if not raw_tuple:
            return None
        raw, expires_at = raw_tuple
        if expires_at <= int(time.time()):
            _MEMORY_STORE.pop(key, None)
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None


# PUBLIC_INTERFACE
def consume_oauth_state(state: str) -> Optional[Dict[str, Any]]:
    """Atomically read and delete the OAuth state payload for one-time use."""
    key = _namespace_key(state)
    client = _get_redis_client()
    if client:
        # Redis doesn't have native GETDEL on very old versions. Try GETDEL, fallback to pipeline.
        try:
            raw = client.execute_command("GETDEL", key)
        except Exception:
            pipe = client.pipeline()
            pipe.get(key)
            pipe.delete(key)
            raw, _ = pipe.execute()
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None
    # Memory fallback
    _prune_memory_store()
    with _MEMORY_LOCK:
        raw_tuple = _MEMORY_STORE.pop(key, None)
    if not raw_tuple:
        return None
    raw, _ = raw_tuple
    try:
        return json.loads(raw)
    except Exception:
        return None


# PUBLIC_INTERFACE
def export_oauth_state_diagnostics(limit: int = 50) -> Dict[str, Any]:
    """Export safe diagnostics info for current state backend."""
    client = _get_redis_client()
    if client:
        # Only return counts to avoid scanning entire keyspace on large deployments.
        # Attempt a lightweight SCAN for our namespace up to 'limit'.
        count = 0
        try:
            cursor = 0
            pattern = _namespace_key("*")
            while True:
                cursor, keys = client.scan(cursor=cursor, match=pattern, count=limit)
                count += len(keys or [])
                if cursor == 0 or count >= limit:
                    break
        except Exception as e:
            _logger.warning("Redis SCAN failed for diagnostics: %s", e)
        return {
            "backend": "redis",
            "approxActiveStates": count,
            "ttlSeconds": _get_ttl_seconds(),
        }
    # Memory fallback
    _prune_memory_store()
    with _MEMORY_LOCK:
        active = len(_MEMORY_STORE)
    return {
        "backend": "memory",
        "approxActiveStates": active,
        "ttlSeconds": _get_ttl_seconds(),
    }
