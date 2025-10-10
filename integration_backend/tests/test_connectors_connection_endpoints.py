from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)

def test_list_connectors_empty():
    resp = client.get("/connectors", headers={"X-Tenant-Id": "t1"})
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert any(x["id"] == "jira" for x in data)

def test_get_connection_not_connected():
    resp = client.get("/connectors/jira/connection", headers={"X-Tenant-Id": "t1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["connected"] is False

def test_patch_and_delete_connection():
    # set base_url and pat gated off -> expect validation error if not enabled
    resp = client.patch("/connectors/jira/connection", headers={"X-Tenant-Id": "t1"}, json={"base_url": "https://foo.atlassian.net"})
    assert resp.status_code == 200
    # delete ok
    resp = client.delete("/connectors/jira/connection", headers={"X-Tenant-Id": "t1"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
