import logging
from typing import Any, Dict, List, Optional
import requests

logger = logging.getLogger(__name__)

class ConfluenceClientError(Exception):
    def __init__(self, message: str, status: Optional[int] = None, retry_after: Optional[int] = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class ConfluenceClient:
    """Minimal Confluence client used for list/search/create with normalized results."""
    def __init__(self, access_token: Optional[str], refresh_token: Optional[str], expires_at: Optional[int], base_url: Optional[str], timeout: int = 20):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at
        self.base_url = base_url or ""
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        return headers

    def _handle(self, resp: requests.Response) -> Dict[str, Any]:
        if resp.status_code >= 400:
            retry_after = None
            if resp.status_code == 429:
                ra = resp.headers.get("Retry-After")
                try:
                    retry_after = int(ra) if ra else None
                except Exception:
                    retry_after = None
            try:
                data = resp.json()
            except Exception:
                data = {"error": resp.text}
            raise ConfluenceClientError(str(data), status=resp.status_code, retry_after=retry_after)
        try:
            return resp.json()
        except Exception:
            return {}

    def list_spaces(self, limit: int = 25, cursor: Optional[str] = None) -> Dict[str, Any]:
        # Minimal: if no base_url available, return empty stub
        if not self.base_url:
            return {"items": []}
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        url = f"{self.base_url}/wiki/api/v2/spaces"
        resp = requests.get(url, headers=self._headers(), params=params, timeout=self.timeout)
        data = self._handle(resp)
        items = []
        for s in data.get("results", []):
            items.append({"id": s.get("id"), "key": s.get("key"), "name": s.get("name")})
        return {"items": items, "next_cursor": data.get("cursor")}

    def search(self, q: str, limit: int = 10) -> List[Dict[str, Any]]:
        if not self.base_url:
            return []
        params = {"query": q, "limit": limit}
        url = f"{self.base_url}/wiki/api/v2/pages/search"
        resp = requests.get(url, headers=self._headers(), params=params, timeout=self.timeout)
        data = self._handle(resp)
        items: List[Dict[str, Any]] = []
        for page in data.get("results", []):
            items.append(
                {
                    "id": str(page.get("id")),
                    "title": page.get("title") or "",
                    "url": f"{self.base_url}/wiki/spaces/{(page.get('space') or {}).get('key')}/pages/{page.get('id')}",
                    "type": "page",
                    "icon": None,
                    "snippet": None,
                    "metadata": {"space": (page.get("space") or {}).get("key")},
                }
            )
        return items

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.base_url:
            raise ConfluenceClientError("Confluence base_url not set", status=400)
        url = f"{self.base_url}/wiki/api/v2/pages"
        resp = requests.post(url, headers=self._headers(), json=payload, timeout=self.timeout)
        data = self._handle(resp)
        return {"id": str(data.get("id")), "url": data.get("url"), "title": data.get("title"), "metadata": data}
