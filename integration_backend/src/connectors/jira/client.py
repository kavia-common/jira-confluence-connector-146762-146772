import time
import os
import logging
from typing import Any, Dict, List, Optional
import requests

logger = logging.getLogger(__name__)

JIRA_API_ROOT = "https://api.atlassian.com/ex/jira"

class JiraClientError(Exception):
    """Wrapper for Jira client error with status and retry info."""
    def __init__(self, message: str, status: Optional[int] = None, retry_after: Optional[int] = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class JiraAuth:
    """Holds auth credentials and expiry for Jira requests."""
    def __init__(
        self,
        access_token: Optional[str],
        refresh_token: Optional[str],
        expires_at: Optional[int],
        base_url: Optional[str] = None,
        pat: Optional[str] = None,
    ):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at
        self.base_url = base_url
        self.pat = pat  # PAT/API key fallback for Atlassian (env gated)


class JiraClient:
    """Lightweight Jira REST client with normalization, pagination and retries."""
    def __init__(self, auth: JiraAuth, enable_pkce: bool = False, timeout: int = 20):
        self.auth = auth
        self.timeout = timeout
        self.enable_pkce = enable_pkce

    def _headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.auth.pat:
            headers["Authorization"] = f"Bearer {self.auth.pat}"
        elif self.auth.access_token:
            headers["Authorization"] = f"Bearer {self.auth.access_token}"
        return headers

    def refresh_token_if_needed(self, skew: int = 120) -> bool:
        """Refresh if expires_at within 'skew' seconds. Returns True if refreshed."""
        if self.auth.pat:
            return False
        if not self.auth.expires_at or not self.auth.refresh_token:
            return False
        now = int(time.time())
        if self.auth.expires_at - now > skew:
            return False
        return self._refresh()

    def try_refresh_on_unauthorized(self) -> bool:
        if self.auth.pat:
            return False
        if not self.auth.refresh_token:
            return False
        return self._refresh()

    def _refresh(self) -> bool:
        """Exchange refresh_token for new tokens."""
        token_url = "https://auth.atlassian.com/oauth/token"
        client_id = os.getenv("NEXT_PUBLIC_ATLASSIAN_CLIENT_ID") or os.getenv("NEXT_PUBLIC_JIRA_OAUTH_CLIENT_ID")
        client_secret = os.getenv("NEXT_PUBLIC_ATLASSIAN_CLIENT_SECRET") or os.getenv("NEXT_PUBLIC_JIRA_OAUTH_CLIENT_SECRET")

        if not client_id or not client_secret:
            logger.warning("Missing Atlassian client credentials; cannot refresh")
            return False

        payload = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": self.auth.refresh_token,
        }
        try:
            resp = requests.post(token_url, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            raise JiraClientError(f"Refresh failed: {e}") from e
        if resp.status_code != 200:
            raise JiraClientError("Refresh failed", status=resp.status_code)
        data = resp.json()
        self.auth.access_token = data.get("access_token")
        expires_in = data.get("expires_in", 3600)
        self.auth.expires_at = int(time.time()) + int(expires_in)
        # Atlassian returns a new refresh_token sometimes
        if data.get("refresh_token"):
            self.auth.refresh_token = data.get("refresh_token")
        return True

    def _handle_response(self, resp: requests.Response) -> Dict[str, Any]:
        if resp.status_code == 204:
            return {}
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
            raise JiraClientError(str(data), status=resp.status_code, retry_after=retry_after)
        try:
            return resp.json()
        except ValueError:
            return {}

    def _cloud_id(self) -> Optional[str]:
        """Resolve cloudId from accessible-resources API."""
        url = "https://api.atlassian.com/oauth/token/accessible-resources"
        try:
            resp = requests.get(url, headers=self._headers(), timeout=self.timeout)
            data = self._handle_response(resp)
        except JiraClientError as e:
            raise e
        arr = data if isinstance(data, list) else []
        for it in arr:
            if it.get("scopes"):
                return it.get("id")
        return arr[0]["id"] if arr else None

    def list_projects(self, limit: int = 25, cursor: Optional[str] = None) -> Dict[str, Any]:
        cloud_id = self._cloud_id()
        if not cloud_id:
            raise JiraClientError("cloudId not found", status=404)
        params = {"maxResults": limit}
        if cursor:
            params["startAt"] = int(cursor)
        url = f"{JIRA_API_ROOT}/{cloud_id}/rest/api/3/project/search"
        resp = requests.get(url, headers=self._headers(), params=params, timeout=self.timeout)
        data = self._handle_response(resp)
        items: List[Dict[str, Any]] = []
        for p in data.get("values", []):
            items.append(
                {
                    "id": p.get("id"),
                    "key": p.get("key"),
                    "name": p.get("name"),
                    "url": p.get("self"),
                    "type": p.get("projectTypeKey"),
                }
            )
        next_cursor = None
        if data.get("isLast") is False:
            next_cursor = (data.get("startAt", 0) + data.get("maxResults", limit))
        return {"items": items, "next_cursor": str(next_cursor) if next_cursor is not None else None}

    def search(self, q: str, limit: int = 10, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Search issues by JQL (q) and normalize to SearchResultItem."""
        cloud_id = self._cloud_id()
        if not cloud_id:
            raise JiraClientError("cloudId not found", status=404)
        jql = q or "order by created DESC"
        body = {"jql": jql, "maxResults": limit, "fields": ["summary", "issuetype", "priority", "status", "project"]}
        url = f"{JIRA_API_ROOT}/{cloud_id}/rest/api/3/search"
        resp = requests.post(url, headers=self._headers(), json=body, timeout=self.timeout)
        data = self._handle_response(resp)
        items: List[Dict[str, Any]] = []
        for issue in data.get("issues", []):
            key = issue.get("key")
            fields = issue.get("fields") or {}
            items.append(
                {
                    "id": key,
                    "title": fields.get("summary") or key,
                    "url": f"https://id.atlassian.com/login?continue=https%3A%2F%2Fapi.atlassian.com%2Fex%2Fjira%2F{cloud_id}%2Frest%2Fapi%2F3%2Fissue%2F{key}",
                    "type": "issue",
                    "icon": None,
                    "snippet": None,
                    "metadata": {
                        "status": (fields.get("status") or {}).get("name"),
                        "priority": (fields.get("priority") or {}).get("name"),
                        "project": ((fields.get("project") or {}).get("key")),
                    },
                }
            )
        return items

    def create(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Create a resource; for now, support issue creation if fields provided."""
        cloud_id = self._cloud_id()
        if not cloud_id:
            raise JiraClientError("cloudId not found", status=404)
        url = f"{JIRA_API_ROOT}/{cloud_id}/rest/api/3/issue"
        resp = requests.post(url, headers=self._headers(), json=payload, timeout=self.timeout)
        data = self._handle_response(resp)
        issue_id = data.get("key") or data.get("id")
        return {"id": str(issue_id), "url": data.get("self"), "title": None, "metadata": data}
