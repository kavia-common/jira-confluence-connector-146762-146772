from typing import Optional, Dict, Any
import threading
import time

# In-memory token storage for demo. Replace with DB in production.
_STORE: Dict[str, Dict[str, Dict[str, Any]] ] = {}
_LOCK = threading.Lock()

class TokenStore:
    """Simple thread-safe token store keyed by tenant and provider."""

    def get_token(self, tenant_id: str, provider: str) -> Optional[Dict[str, Any]]:
        with _LOCK:
            return (_STORE.get(tenant_id) or {}).get(provider)

    def save_token(self, tenant_id: str, provider: str, record: Dict[str, Any]) -> None:
        with _LOCK:
            _STORE.setdefault(tenant_id, {})
            record = dict(record)
            # Ensure fields for status
            record.setdefault("refreshed_at", int(time.time()))
            _STORE[tenant_id][provider] = record

    def delete_token(self, tenant_id: str, provider: str) -> None:
        with _LOCK:
            if tenant_id in _STORE and provider in _STORE[tenant_id]:
                del _STORE[tenant_id][provider]
