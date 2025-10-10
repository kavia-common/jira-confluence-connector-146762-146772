import pytest
from fastapi.testclient import TestClient
from src.api.main import app

@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_ID", "abc123")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_SECRET", "secret")
    monkeypatch.setenv("JIRA_REDIRECT_URI", "https://example.com/auth/jira/callback")
    yield

def test_login_returns_authorize_url_json_and_sets_cookie():
    client = TestClient(app)
    r = client.get("/auth/jira/login")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "url" in data and "auth.atlassian.com/authorize" in data["url"]
    assert "client_id=abc123" in data["url"]
    assert "redirect_uri=" in data["url"]
    # cookie must be set
    cookies = r.cookies
    assert cookies.get("jira_oauth_state")

def test_callback_422_when_missing_state():
    client = TestClient(app)
    r = client.get("/auth/jira/callback")
    assert r.status_code == 422

def test_callback_redirects_when_state_cookie_matches(monkeypatch):
    client = TestClient(app)
    # First, call login to get cookie and state part (we will re-use cookie + embed in state)
    r = client.get("/auth/jira/login")
    assert r.status_code == 200
    cookie = r.cookies.get("jira_oauth_state")
    assert cookie
    import json as _json
    st = _json.dumps({"csrf": cookie, "tenant_id": "default"})
    # Mock JiraConnector.oauth_callback to avoid external call
    from src.connectors.jira import impl as ji
    def fake_oauth_callback(self, code: str, tenant_id: str, state: str):
        return True
    monkeypatch.setattr(ji.JiraConnector, "oauth_callback", fake_oauth_callback, raising=True)
    r2 = client.get("/auth/jira/callback", params={"code": "good-code", "state": st})
    # Should redirect
    assert r2.status_code in (302, 303), r2.text
