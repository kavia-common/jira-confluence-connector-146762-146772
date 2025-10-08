from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .models import SearchResultItem, CreateResult, ConnectionStatus


class BaseConnector(ABC):
    """
    Abstract interface for all connectors.

    Implementations must handle:
    - OAuth flow (authorize URL, callback)
    - Token refresh (if needed)
    - Normalized search and create operations
    - Connection status reporting
    """

    connector_id: str = "base"

    # PUBLIC_INTERFACE
    @abstractmethod
    def search(
        self,
        query: str,
        tenant_id: str,
        limit: int = 10,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[SearchResultItem]:
        """Search for resources on the provider, returning normalized items."""

    # PUBLIC_INTERFACE
    @abstractmethod
    def create(self, payload: Dict[str, Any], tenant_id: str) -> CreateResult:
        """Create a resource on the provider, returning a normalized CreateResult."""

    # PUBLIC_INTERFACE
    @abstractmethod
    def get_resource(self, key: str, tenant_id: str) -> Dict[str, Any]:
        """Fetch a provider-specific resource by key/id. Return raw or normalized mapping."""

    # PUBLIC_INTERFACE
    @abstractmethod
    def connection_status(self, tenant_id: str) -> ConnectionStatus:
        """Return connection status for a tenant, including scopes and expiry info."""

    # PUBLIC_INTERFACE
    @abstractmethod
    def oauth_authorize_url(
        self, tenant_id: str, state: Optional[str] = None, scopes: Optional[str] = None
    ) -> str:
        """
        Build and return the provider's OAuth 2.0 authorize URL.

        Tenant id should be encoded in state or otherwise preserved.
        """

    # PUBLIC_INTERFACE
    @abstractmethod
    def oauth_callback(
        self, code: str, tenant_id: str, state: Optional[str] = None
    ) -> ConnectionStatus:
        """
        Handle OAuth callback: exchange code for tokens and persist for the tenant.
        Return updated ConnectionStatus.
        """

    # PUBLIC_INTERFACE
    @abstractmethod
    def refresh_token_if_needed(self, tenant_id: str) -> ConnectionStatus:
        """
        If token is expired or near expiry, refresh and persist.
        Return current/updated ConnectionStatus.
        """
