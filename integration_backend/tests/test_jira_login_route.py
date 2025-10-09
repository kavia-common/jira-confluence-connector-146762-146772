import pytest
from fastapi.testclient import TestClient

# Import the app from main
from src.api.main import app

@pytest.fixture(autouse=True)
def setup_env(monkeypatch):
    # Minimal required env to construct URL
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_ID", "test_client_id_123")
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_SECRET", "shhh_secret")
    monkeypatch.setenv("JIRA_REDIRECT_URI", "https://example.com/auth/jira/callback")
    yield
    # teardown would be automatic via monkeypatch

def test_jira_login_get_returns_url_json():
    client = TestClient(app)
    r = client.get("/auth/jira/login")
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, dict)
    # Response model wraps directly { "url": ... } due to response_model=OAuthAuthorizeURL
    assert "url" in data, data
    assert "auth.atlassian.com/authorize" in data["url"]
    assert "client_id=test_client_id_123" in data["url"]
    assert "redirect_uri=" in data["url"]

def test_jira_login_options_preflight():
    client = TestClient(app)
    # Simulate CORS preflight
    headers = {
        "Origin": "https://example.com",
        "Access-Control-Request-Method": "GET",
    }
    r = client.options("/auth/jira/login", headers=headers)
    assert r.status_code == 200
    # Middleware should add CORS headers
    assert "access-control-allow-origin" in r.headers
