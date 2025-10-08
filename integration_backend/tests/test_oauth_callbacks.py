import os
import sys
from typing import Any

# Ensure integration_backend/src is importable
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# Configure test database path before importing app modules
TEST_DB_PATH = os.path.join(BASE_DIR, "test_integration.db")
if os.path.exists(TEST_DB_PATH):
    os.remove(TEST_DB_PATH)

os.environ["INTEGRATION_DB_URL"] = f"sqlite:///{TEST_DB_PATH}"
os.environ["ATLASSIAN_CLOUD_BASE_URL"] = "https://example.atlassian.net"
os.environ["APP_FRONTEND_URL"] = "http://localhost:3000"
# Jira OAuth env
os.environ["JIRA_OAUTH_CLIENT_ID"] = "test_client_id"
os.environ["JIRA_OAUTH_CLIENT_SECRET"] = "test_client_secret"
os.environ["JIRA_OAUTH_REDIRECT_URI"] = "http://localhost:3001/auth/jira/callback"
# Confluence can reuse Jira config via fallbacks

from fastapi.testclient import TestClient  # noqa: E402
import httpx  # noqa: E402

# Import after env setup
from src.api.main import app  # noqa: E402
from src.db.config import SessionLocal  # noqa: E402
from src.db.models import User  # noqa: E402


class DummyResp:
    def __init__(self, payload: dict[str, Any], status_code: int = 200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


class DummyAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json_payload=None, headers=None):
        # Always return a successful token exchange response
        return DummyResp(
            {
                "access_token": "test_access_token",
                "refresh_token": "test_refresh_token",
                "expires_in": 3600,
                "token_type": "Bearer",
            },
            status_code=200,
        )


def _patch_httpx(monkeypatch):
    monkeypatch.setattr(httpx, "AsyncClient", DummyAsyncClient)


def _clear_users():
    # Clear all users from the test DB between tests
    with SessionLocal() as db:
        try:
            db.query(User).delete()
            db.commit()
        except Exception:
            db.rollback()
            raise


def test_jira_callback_creates_placeholder_user_when_none(monkeypatch):
    _patch_httpx(monkeypatch)
    _clear_users()

    client = TestClient(app, follow_redirects=False)
    resp = client.get("/auth/jira/callback?code=abc123&state=")
    assert resp.status_code in (302, 307)

    with SessionLocal() as db:
        users = db.query(User).all()
        assert len(users) == 1
        u = users[0]
        assert u.jira_token == "test_access_token"
        assert u.jira_refresh_token == "test_refresh_token"
        assert isinstance(u.email, str) and "@example." in u.email


def test_jira_callback_uses_user_id_from_state(monkeypatch):
    _patch_httpx(monkeypatch)
    _clear_users()

    # Pre-create a user
    with SessionLocal() as db:
        user = User(email="state-user@example.local", display_name="State User")
        db.add(user)
        db.commit()
        db.refresh(user)
        user_id = user.id

    client = TestClient(app, follow_redirects=False)
    # Provide state hint user_id to target the existing user
    resp = client.get(f"/auth/jira/callback?code=zzz999&state=user_id={user_id}")
    assert resp.status_code in (302, 307)

    with SessionLocal() as db:
        users = db.query(User).order_by(User.id.asc()).all()
        assert len(users) == 1
        u = users[0]
        assert u.id == user_id
        assert u.jira_token == "test_access_token"
        assert u.jira_refresh_token == "test_refresh_token"


def test_confluence_callback_creates_placeholder_user_when_none(monkeypatch):
    _patch_httpx(monkeypatch)
    _clear_users()

    client = TestClient(app, follow_redirects=False)
    resp = client.get("/auth/confluence/callback?code=abc123&state=")
    assert resp.status_code in (302, 307)

    with SessionLocal() as db:
        users = db.query(User).all()
        assert len(users) == 1
        u = users[0]
        # Tokens are stored on confluence_* fields
        assert u.confluence_token == "test_access_token"
        assert u.confluence_refresh_token == "test_refresh_token"
        assert isinstance(u.email, str) and "@example." in u.email
