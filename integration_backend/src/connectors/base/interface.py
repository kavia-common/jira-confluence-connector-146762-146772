from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .models import SearchResultItem, CreateResult, ConnectionStatus


class ConnectorInterface(ABC):
    """Abstract interface for all connectors."""

    connector_id: str = "base"

    # PUBLIC_INTERFACE
    @abstractmethod
    def status(self, tenant_id: str) -> ConnectionStatus:
        """Return connection status for a tenant."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def search(self, tenant_id: str, q: str, limit: int = 10, filters: Optional[Dict[str, Any]] = None) -> List[SearchResultItem]:
        """Search provider for resources and return normalized items."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def create(self, tenant_id: str, payload: Dict[str, Any]) -> CreateResult:
        """Create a resource at provider and return normalized result."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def list_projects(self, tenant_id: str) -> List[Dict[str, Any]]:
        """List projects for the tenant (normalized dicts)."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def delete_connection(self, tenant_id: str) -> None:
        """Delete/revoke the connection for the tenant."""
        raise NotImplementedError

    # PUBLIC_INTERFACE
    @abstractmethod
    def rotate_connection(self, tenant_id: str) -> ConnectionStatus:
        """Force refresh/rotate tokens for the tenant and return latest status."""
        raise NotImplementedError
