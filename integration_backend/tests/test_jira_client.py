import os
import pytest
from fastapi import HTTPException

from integration_backend.src.db.token_store import save_tokens, delete_tokens
from integration_backend.src.connectors.jira.client import JiraClient

def setup_module():
    os.environ["JIRA_OAUTH_CLIENT_ID"] = "cid"
    os.environ["JIRA_OAUTH_CLIENT_SECRET"] = "secret"
    os.environ["JIRA_REDIRECT_URI"] = "http://localhost/callback"

def teardown_module():
    delete_tokens("jira", "default")

def test_unauthorized_without_tokens():
    with pytest.raises(HTTPException) as ei:
        JiraClient(tenant_id="default").ensure_tokens()
    assert ei.value.status_code == 401
    assert ei.value.detail["code"] in ("UNAUTHORIZED", "TOKEN_EXPIRED")

def test_expired_without_refresh_is_401():
    save_tokens("jira", "default", access_token="a", refresh_token=None, expires_at=0, scopes=["s1"])
    with pytest.raises(HTTPException) as ei:
        JiraClient(tenant_id="default").ensure_tokens()
    assert ei.value.status_code == 401
    assert ei.value.detail["code"] == "TOKEN_EXPIRED"
