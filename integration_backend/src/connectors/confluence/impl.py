from __future__ import annotations

import time
import json
from typing import Any, Dict, List, Optional

import httpx
from fastapi import HTTPException, status

from src.connectors.base.interface import BaseConnector
from src.connectors.base.models import SearchResultItem, CreateResult, ConnectionStatus
from src.db.token_store import save_tokens, get_tokens, get_token_record
from src.api.oauth_config import get_confluence_oauth_config, build_atlassian_authorize_url


class ConfluenceConnector(BaseConnector):
    """Confluence connector implementation using Atlassian OAuth 2.0."""

    connector_id: str = "confluence"

    def _default_scopes(self) -> str:
        return "read:confluence-content.all read:confluence-space.summary offline_access"

    def oauth_authorize_url(
        self, tenant_id: str, state: Optional[str] = None, scopes: Optional[str] = None
    ) -> str:
        cfg = get_confluence_oauth_config()
        client_id = cfg.get("client_id") or ""
        redirect_uri = cfg.get("redirect_uri") or ""
        scopes = scopes or self._default_scopes()

        compound_state: Optional[str] = None
        if state:
            try:
                compound_state = json.dumps({"tenant_id": tenant_id, "state": state}, separators=(",", ":"))
            except Exception:
                compound_state = state
        else:
            compound_state = json.dumps({"tenant_id": tenant_id}, separators=(",", ":"))

        return build_atlassian_authorize_url(
            client_id=client_id, redirect_uri=redirect_uri, scopes=scopes, state=compound_state
        )

    def oauth_callback(
        self, code: str, tenant_id: str, state: Optional[str] = None
    ) -> ConnectionStatus:
        cfg = get_confluence_oauth_config()
        client_id = cfg.get("client_id")
        client_secret = cfg.get("client_secret")
        redirect_uri = cfg.get("redirect_uri")
        if not client_id or not client_secret or not redirect_uri:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Confluence OAuth is not configured.",
            )

        token_url = "https://auth.atlassian.com/oauth/token"
        data = {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }
        with httpx.Client(timeout=20.0) as client:
            resp = client.post(token_url, json=data, headers={"Content-Type": "application/json"})
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail="Token exchange failed")
        tj = resp.json()
        scopes = tj.get("scope", None)
        expires_in = int(tj.get("expires_in") or 0)
        expires_at = int(time.time()) + expires_in if expires_in > 0 else None

        save_tokens(
            db=self._db,  # type: ignore[attr-defined]
            connector_id=self.connector_id,
            tenant_id=tenant_id,
            tokens={"access_token": tj.get("access_token"), "refresh_token": tj.get("refresh_token")},
            scopes=scopes,
            expires_at=expires_at,
            metadata={"token_type": tj.get("token_type")},
        )
        granted_scopes = (scopes.split() if isinstance(scopes, str) and scopes else None)
        return ConnectionStatus(connected=True, scopes=granted_scopes, expires_at=expires_at)

    def connection_status(self, tenant_id: str) -> ConnectionStatus:
        rec = get_token_record(self._db, self.connector_id, tenant_id)  # type: ignore[attr-defined]
        if not rec:
            return ConnectionStatus(connected=False, scopes=None, expires_at=None)
        scopes = rec.scopes.split() if rec.scopes else None
        return ConnectionStatus(connected=True, scopes=scopes, expires_at=rec.expires_at, error=rec.last_error)

    def refresh_token_if_needed(self, tenant_id: str) -> ConnectionStatus:
        rec = get_token_record(self._db, self.connector_id, tenant_id)  # type: ignore[attr-defined]
        if not rec:
            return ConnectionStatus(connected=False, scopes=None, expires_at=None)
        now = int(time.time())
        safe_window = 120
        if rec.expires_at and rec.expires_at - now > safe_window:
            scopes = rec.scopes.split() if rec.scopes else None
            return ConnectionStatus(connected=True, scopes=scopes, expires_at=rec.expires_at)

        cfg = get_confluence_oauth_config()
        client_id = cfg.get("client_id")
        client_secret = cfg.get("client_secret")
        if not client_id or not client_secret:
            return ConnectionStatus(connected=False, scopes=None, expires_at=rec.expires_at, error="oauth_config_missing")

        tokens = get_tokens(self._db, self.connector_id, tenant_id)  # type: ignore[attr-defined]
        if not tokens or not tokens.get("refresh_token"):
            return ConnectionStatus(connected=False, scopes=None, expires_at=rec.expires_at, error="no_refresh_token")

        with httpx.Client(timeout=20.0) as client:
            r = client.post(
                "https://auth.atlassian.com/oauth/token",
                json={
                    "grant_type": "refresh_token",
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "refresh_token": tokens.get("refresh_token"),
                },
                headers={"Content-Type": "application/json"},
            )
        if r.status_code != 200:
            return ConnectionStatus(connected=False, scopes=None, expires_at=rec.expires_at, error="refresh_failed")
        tj = r.json()
        scopes = tj.get("scope", rec.scopes)
        expires_in = int(tj.get("expires_in") or 0)
        expires_at = int(time.time()) + expires_in if expires_in > 0 else None
        save_tokens(
            db=self._db,  # type: ignore[attr-defined]
            connector_id=self.connector_id,
            tenant_id=tenant_id,
            tokens={"access_token": tj.get("access_token"), "refresh_token": tj.get("refresh_token")},
            scopes=scopes,
            expires_at=expires_at,
        )
        return ConnectionStatus(
            connected=True,
            scopes=scopes.split() if isinstance(scopes, str) else None,
            expires_at=expires_at,
        )

    def search(
        self, query: str, tenant_id: str, limit: int = 10, filters: Optional[Dict[str, Any]] = None
    ) -> List[SearchResultItem]:
        items: List[SearchResultItem] = []
        for i in range(min(max(limit, 1), 25)):
            items.append(
                SearchResultItem(
                    id=f"PAGE-{i}",
                    title=f"Confluence page matching '{query}' #{i}",
                    url="https://example.atlassian.net/wiki/spaces/SPACE/pages/123",
                    type="page",
                    snippet="Stubbed result. Connect to fetch real pages.",
                    metadata={"tenant_id": tenant_id, "filters": filters or {}},
                )
            )
        return items

    def create(self, payload: Dict[str, Any], tenant_id: str) -> CreateResult:
        # For now, require connection but return stub
        tokens = get_tokens(self._db, self.connector_id, tenant_id)  # type: ignore[attr-defined]
        if not tokens or not tokens.get("access_token"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Connector not connected for tenant")
        return CreateResult(
            id="PAGE-12345",
            url="https://example.atlassian.net/wiki/spaces/SPACE/pages/12345",
            title=payload.get("title") or "Demo Created Page",
            metadata={"tenant_id": tenant_id, "payload": payload},
        )

    def get_resource(self, key: str, tenant_id: str) -> Dict[str, Any]:
        return {
            "id": key,
            "title": f"Confluence resource {key}",
            "url": f"https://example.atlassian.net/wiki/spaces/SPACE/pages/{key}",
            "metadata": {"tenant_id": tenant_id},
        }

    def with_db(self, db) -> "ConfluenceConnector":
        self._db = db  # type: ignore[attr-defined]
        return self
