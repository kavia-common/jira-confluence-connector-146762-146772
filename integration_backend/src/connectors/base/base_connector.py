from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .models import SearchResultItem, CreateResult, ConnectionStatus


class BaseConnector(ABC):
    """Base abstract class for connectors to share a consistent interface.

    This mirrors and complements ConnectorInterface; existing implementations
    import BaseConnector, so we provide that symbol with abstract methods.
    """

    connector_id: str = "base"

    # Allow connectors to attach a DB/session or other context
    def with_db(self, db: Any) -> "BaseConnector":
        """Attach a DB/session handle to this connector and return self."""
        self._db = db  # type: ignore[attr-defined]
        return self

    # PUBLIC_INTERFACE
    @abstractmethod
    def oauth_authorize_url(self, tenant_id: str, state: Optional[str] = None, scopes: Optional[str] = None) -> str:
        """Build provider-specific OAuth authorize URL."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def oauth_callback(self, code: str, tenant_id: str, state: Optional[str] = None) -> ConnectionStatus:
        """Process OAuth callback and persist tokens for the tenant."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def connection_status(self, tenant_id: str) -> ConnectionStatus:
        """Return connection status for a tenant."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def refresh_token_if_needed(self, tenant_id: str) -> ConnectionStatus:
        """Optionally refresh tokens if close to expiry; return latest status."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def search(self, query: str, tenant_id: str, limit: int = 10, filters: Optional[Dict[str, Any]] = None) -> List[SearchResultItem]:
        """Search provider for resources and return normalized items."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def create(self, payload: Dict[str, Any], tenant_id: str) -> CreateResult:
        """Create a resource at provider and return normalized result."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def get_resource(self, key: str, tenant_id: str) -> Dict[str, Any]:
        """Fetch a resource by key/id and return provider-normalized dict."""
        raise NotImplementedError
