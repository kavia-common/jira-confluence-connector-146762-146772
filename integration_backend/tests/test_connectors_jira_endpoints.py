import os
from fastapi.testclient import TestClient

from integration_backend.src.api.main import app
from integration_backend.src.db.token_store import save_tokens, delete_tokens

client = TestClient(app)

def setup_module():
    os.environ["JIRA_OAUTH_CLIENT_ID"] = "cid"
    os.environ["JIRA_OAUTH_CLIENT_SECRET"] = "secret"
    os.environ["JIRA_REDIRECT_URI"] = "http://localhost/callback"

def teardown_module():
    delete_tokens("jira", "default")

def test_connectors_list_includes_jira():
    r = client.get("/connectors", headers={"X-Tenant-Id": "default"})
    assert r.status_code == 200
    data = r.json()
    ids = [c["id"] for c in data["connectors"]]
    assert "jira" in ids

def test_create_issue_validation():
    # Missing required fields -> 422 via VALIDATION_ERROR mapping
    r = client.post("/connectors/jira/create", json={"resource": "issue"}, headers={"X-Tenant-Id": "default"})
    assert r.status_code in (400, 422)

def test_delete_connection_ok():
    # seed tokens and then delete
    save_tokens("jira", "default", access_token="a", refresh_token="r", expires_at=999999, scopes=["x"])
    r = client.delete("/connectors/jira/connection", headers={"X-Tenant-Id": "default"})
    assert r.status_code == 200
    # status should show disconnected
    s = client.get("/connectors/jira/status", headers={"X-Tenant-Id": "default"})
    assert s.status_code == 200
    assert s.json()["connected"] is False
