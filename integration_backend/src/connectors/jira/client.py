import os
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import status as http_status

from ...db.token_store import get_tokens, save_tokens, update_meta
from ...api.errors import error_response

LOG = logging.getLogger(__name__)

ATLASSIAN_AUTH = "https://auth.atlassian.com"
ATLASSIAN_API = "https://api.atlassian.com"

DEFAULT_TIMEOUT = 20.0
EARLY_REFRESH_WINDOW_SEC = 120  # refresh if expiring within 2 minutes

class JiraClient:
    """
    Lightweight Jira API client for Atlassian Cloud REST v3.

    Handles:
    - Tenant-scoped token retrieval
    - Early refresh using refresh_token and expiry
    - Retry on 401 once after refresh
    - 429 detection with retry_after
    """

    def __init__(self, tenant_id: str, request_id: Optional[str] = None):
        self.tenant_id = tenant_id or "default"
        self.request_id = request_id or f"req-{int(time.time()*1000)}"
        self.client_id = os.getenv("JIRA_OAUTH_CLIENT_ID")
        self.client_secret = os.getenv("JIRA_OAUTH_CLIENT_SECRET")
        self.redirect_uri = os.getenv("JIRA_REDIRECT_URI")
        if not self.client_id or not self.client_secret or not self.redirect_uri:
            raise error_response(
                "CONFIG_ERROR",
                "Missing required env vars for Jira OAuth: JIRA_OAUTH_CLIENT_ID, JIRA_OAUTH_CLIENT_SECRET, JIRA_REDIRECT_URI",
                status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    # PUBLIC_INTERFACE
    def ensure_tokens(self) -> Dict[str, Any]:
        """
        Ensure access token present and not expiring within EARLY_REFRESH_WINDOW_SEC.
        Refresh if needed using refresh_token.
        """
        rec = get_tokens("jira", self.tenant_id)
        if not rec:
            raise error_response("UNAUTHORIZED", "No Jira connection for tenant", status_code=http_status.HTTP_401_UNAUTHORIZED)

        exp = rec.get("expires_at")
        now = int(time.time())
        if exp is None or exp - now <= EARLY_REFRESH_WINDOW_SEC:
            # attempt refresh if refresh_token available
            if rec.get("refresh_token"):
                self._refresh(rec["refresh_token"])
                rec = get_tokens("jira", self.tenant_id) or rec
            else:
                # no refresh token -> treat as expired
                raise error_response("TOKEN_EXPIRED", "Jira token expired and no refresh token", status_code=http_status.HTTP_401_UNAUTHORIZED)
        return rec

    def _refresh(self, refresh_token: str) -> None:
        data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token,
        }
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as c:
            resp = c.post(f"{ATLASSIAN_AUTH}/oauth/token", json=data, headers={"Content-Type": "application/json"})
        if resp.status_code != 200:
            LOG.warning("Jira refresh failed: %s %s", resp.status_code, resp.text)
            update_meta("jira", self.tenant_id, last_error=f"refresh_failed:{resp.status_code}")
            raise error_response("TOKEN_EXPIRED", "Failed to refresh Jira token", status_code=http_status.HTTP_401_UNAUTHORIZED)
        tok = resp.json()
        access = tok.get("access_token")
        new_refresh = tok.get("refresh_token", refresh_token)
        expires_in = tok.get("expires_in")  # seconds
        expires_at = int(time.time()) + int(expires_in or 0)
        scope = tok.get("scope", "")
        scopes = [s for s in scope.split(" ") if s] if isinstance(scope, str) else None
        save_tokens("jira", self.tenant_id, access_token=access, refresh_token=new_refresh, expires_at=expires_at, scopes=scopes, base_url=None, cloud_id=None, last_error=None)
        update_meta("jira", self.tenant_id, refreshed_at=int(time.time()))

    def _authorized_headers(self, token: str) -> Dict[str, str]:
        h = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        # propagate request id for tracing
        h["X-Request-Id"] = self.request_id
        return h

    def _cloud_base_and_id(self, access_token: str) -> Tuple[str, str]:
        # Prefer configured base URL if provided
        env_base = os.getenv("ATLASSIAN_CLOUD_BASE_URL")
        rec = get_tokens("jira", self.tenant_id) or {}
        cached_base = rec.get("base_url")
        cached_cloud = rec.get("cloud_id")

        if env_base and cached_cloud:
            return env_base.rstrip("/"), cached_cloud

        # Discover with accessible resources
        with httpx.Client(timeout=DEFAULT_TIMEOUT) as c:
            resp = c.get(f"{ATLASSIAN_API}/oauth/token/accessible-resources", headers=self._authorized_headers(access_token))
        if resp.status_code != 200:
            if resp.status_code == 401:
                raise error_response("UNAUTHORIZED", "Jira unauthorized while discovering cloud base", status_code=http_status.HTTP_401_UNAUTHORIZED)
            raise error_response("VENDOR_ERROR", f"Failed to discover Jira cloud resources: {resp.status_code}")
        resources = resp.json()
        # Find jira resource
        jira_res = next((r for r in resources if r.get("scopes") and "read:jira-work" in r.get("scopes", []) or r.get("url", "").find("atlassian.net") != -1), None)
        if not jira_res:
            raise error_response("CONFIG_ERROR", "Could not discover Jira Cloud base. Set ATLASSIAN_CLOUD_BASE_URL.")
        base_url = jira_res.get("url") or env_base or cached_base
        cloud_id = jira_res.get("id") or cached_cloud
        if not base_url or not cloud_id:
            raise error_response("CONFIG_ERROR", "Missing base_url or cloud_id for Jira; set ATLASSIAN_CLOUD_BASE_URL or complete OAuth.")
        update_meta("jira", self.tenant_id, base_url=base_url, cloud_id=cloud_id)
        return base_url.rstrip("/"), cloud_id

    def _request_with_refresh(self, method: str, url: str, json_body: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None) -> httpx.Response:
        rec = self.ensure_tokens()
        token = rec["access_token"]

        def do_request(tk: str) -> httpx.Response:
            with httpx.Client(timeout=DEFAULT_TIMEOUT) as c:
                return c.request(method, url, headers=self._authorized_headers(tk), json=json_body, params=params)

        resp = do_request(token)
        if resp.status_code == 401 and rec.get("refresh_token"):
            # one retry after refresh
            self._refresh(rec["refresh_token"])
            rec2 = get_tokens("jira", self.tenant_id) or rec
            resp = do_request(rec2["access_token"])

        if resp.status_code == 429:
            retry = int(resp.headers.get("Retry-After", "0") or "0")
            raise error_response("RATE_LIMITED", "Jira rate limited the request", status_code=429, retry_after=retry)
        return resp

    # PUBLIC_INTERFACE
    def list_projects(self) -> List[Dict[str, Any]]:
        """
        List Jira projects (key, name, projectTypeKey, id).
        """
        rec = self.ensure_tokens()
        base_url, _cloud = self._cloud_base_and_id(rec["access_token"])
        url = f"{base_url}/rest/api/3/project/search"
        resp = self._request_with_refresh("GET", url)
        if resp.status_code != 200:
            raise error_response("VENDOR_ERROR", f"Failed to list projects: {resp.status_code}")
        data = resp.json()
        projects = data.get("values", data if isinstance(data, list) else [])
        normalized: List[Dict[str, Any]] = []
        for p in projects:
            normalized.append({
                "id": str(p.get("id")),
                "key": p.get("key"),
                "name": p.get("name"),
                "url": f"{base_url}/browse/{p.get('key')}" if p.get("key") else None,
                "projectTypeKey": p.get("projectTypeKey"),
            })
        return normalized

    # PUBLIC_INTERFACE
    def search_jql(self, jql: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Search issues using JQL, return normalized SearchResultItem dicts.
        """
        rec = self.ensure_tokens()
        base_url, _cloud = self._cloud_base_and_id(rec["access_token"])
        url = f"{base_url}/rest/api/3/search"
        params = {"jql": jql, "maxResults": min(max(limit, 1), 50)}
        resp = self._request_with_refresh("GET", url, params=params)
        if resp.status_code != 200:
            raise error_response("VENDOR_ERROR", f"Jira search failed: {resp.status_code}")
        js = resp.json()
        issues = js.get("issues", [])
        items: List[Dict[str, Any]] = []
        for it in issues:
            key = it.get("key")
            fields = it.get("fields", {})
            summary = fields.get("summary") or key
            items.append({
                "id": key or str(it.get("id")),
                "title": summary,
                "url": f"{base_url}/browse/{key}" if key else base_url,
                "type": "issue",
                "icon": None,
                "snippet": fields.get("description") if isinstance(fields.get("description"), str) else None,
                "metadata": {
                    "status": (fields.get("status") or {}).get("name"),
                    "assignee": (fields.get("assignee") or {}).get("displayName"),
                    "project": (fields.get("project") or {}).get("key"),
                    "created": fields.get("created"),
                    "updated": fields.get("updated"),
                },
            })
        return items

    # PUBLIC_INTERFACE
    def create_issue(self, project_key: str, summary: str, description: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a Jira issue and return normalized CreateResult dict.
        """
        rec = self.ensure_tokens()
        base_url, _cloud = self._cloud_base_and_id(rec["access_token"])
        url = f"{base_url}/rest/api/3/issue"
        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "issuetype": {"name": "Task"},
            }
        }
        if description:
            payload["fields"]["description"] = description
        resp = self._request_with_refresh("POST", url, json_body=payload)
        if resp.status_code not in (200, 201):
            # Propagate vendor message if available
            try:
                err = resp.json()
            except Exception:
                err = {"error": resp.text}
            raise error_response("VENDOR_ERROR", f"Jira create issue failed: {resp.status_code}", details=err, status_code=resp.status_code)
        js = resp.json()
        key = js.get("key") or js.get("id")
        return {
            "id": key,
            "url": f"{base_url}/browse/{key}" if key else None,
            "title": summary,
            "metadata": js,
        }
