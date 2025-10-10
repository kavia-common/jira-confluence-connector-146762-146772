from fastapi.testclient import TestClient
from src.api.main import app
from src.db.token_store import TokenStore

client = TestClient(app)

def seed_jira_tokens(tenant="t1"):
    store = TokenStore()
    store.save_token(tenant, "jira", {
        "access_token": "at",
        "refresh_token": "rt",
        "expires_at": 9999999999,
        "base_url": "https://example.atlassian.net"
    })

def test_jira_projects_endpoint(monkeypatch):
    seed_jira_tokens()

    class MockClient:
        def __init__(self, *args, **kwargs): pass
        def refresh_token_if_needed(self, *args, **kwargs): return False
        def list_projects(self, limit=25, cursor=None):
            return {"items": [{"id":"1","key":"ABC","name":"Proj","url":"u","type":"software"}]}

    import src.connectors.jira.client as jc
    monkeypatch.setattr(jc, "JiraClient", MockClient)

    resp = client.get("/connectors/jira/projects", headers={"X-Tenant-Id": "t1"})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert data[0]["key"] == "ABC"

def test_jira_search_endpoint(monkeypatch):
    seed_jira_tokens()

    class MockClient:
        def __init__(self, *args, **kwargs): pass
        def refresh_token_if_needed(self, *args, **kwargs): return False
        def search(self, q="", limit=10, filters=None):
            return [{"id": "ISSUE-1", "title": "Bug", "url": "u", "type": "issue", "icon": None, "snippet": None, "metadata": {}}]

    import src.connectors.jira.client as jc
    monkeypatch.setattr(jc, "JiraClient", MockClient)

    resp = client.get("/connectors/jira/search?q=project=ABC", headers={"X-Tenant-Id": "t1"})
    assert resp.status_code == 200
    arr = resp.json()
    assert arr[0]["id"] == "ISSUE-1"
