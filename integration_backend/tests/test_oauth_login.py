from fastapi.testclient import TestClient

# Ensure imports resolve relative to integration_backend
from src.api.main import app

client = TestClient(app)


# PUBLIC_INTERFACE
def test_jira_login_authorize_url_json(monkeypatch):
    """Verify that GET /auth/jira/login?response=json returns the expected authorize URL with correct params."""
    # Set env vars to known values for test
    monkeypatch.setenv("JIRA_OAUTH_CLIENT_ID", "hHwzD9WrTnD6SFcV4tp4zDt9XbB9K9WQ")
    monkeypatch.setenv("JIRA_REDIRECT_URI", "https://vscode-internal-13311-beta.beta01.cloud.kavia.ai:3001/auth/jira/callback")

    r = client.get("/auth/jira/login", params={"response": "json"})
    assert r.status_code == 200
    data = r.json()
    assert "authorize_url" in data
    url = data["authorize_url"]

    # Validate presence of required query params in the URL
    assert url.startswith("https://auth.atlassian.com/authorize?")
    # We don't parse with strict ordering; just check key fragments
    assert "audience=api.atlassian.com" in url
    assert "client_id=hHwzD9WrTnD6SFcV4tp4zDt9XbB9K9WQ" in url
    assert "response_type=code" in url
    assert "prompt=consent" in url
    # scope default should be jira scopes; space encoded as %20
    assert "scope=read%3Ajira-work%20read%3Ajira-user%20offline_access" in url
    assert "redirect_uri=https%3A%2F%2Fvscode-internal-13311-beta.beta01.cloud.kavia.ai%3A3001%2Fauth%2Fjira%2Fcallback" in url
