from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routes.oauth_connectors import router
from integrations.tenant_store import TenantStore


class DummyMSGraphConnector:
    def __init__(self, client_id, client_secret, redirect_uri, scope="offline_access Mail.Read"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def get_authorization_url(self, state=None):
        return f"https://example.test/auth?state={state}"

    def exchange_code(self, code):
        return {"access_token": "token123", "refresh_token": "refresh123", "expires_in": 3600}

    def refresh_token(self, refresh_token):
        return {"access_token": "token456", "refresh_token": refresh_token, "expires_in": 3600}


def _test_client(monkeypatch, connector_cls):
    monkeypatch.setattr("src.api.routes.oauth_connectors.MSGraphConnector", connector_cls)
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_msgraph_start_returns_auth_url(monkeypatch):
    monkeypatch.setenv("MSGRAPH_CLIENT_ID", "cid")
    monkeypatch.setenv("MSGRAPH_CLIENT_SECRET", "secret")
    monkeypatch.setenv("MSGRAPH_REDIRECT", "http://localhost/callback")
    client = _test_client(monkeypatch, DummyMSGraphConnector)

    resp = client.get("/api/v1/integrations/oauth/msgraph/start")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == "default"
    assert body["auth_url"].startswith("https://example.test/auth?")
    assert "state" in body


def test_msgraph_callback_persists_tokens(monkeypatch):
    monkeypatch.setenv("SECRET_BACKEND", "memory")
    monkeypatch.setenv("MSGRAPH_CLIENT_ID", "cid")
    monkeypatch.setenv("MSGRAPH_CLIENT_SECRET", "secret")
    monkeypatch.setenv("MSGRAPH_REDIRECT", "http://localhost/callback")
    client = _test_client(monkeypatch, DummyMSGraphConnector)

    resp = client.get("/api/v1/integrations/oauth/msgraph/callback", params={"code": "abc"})
    assert resp.status_code == 200
    store = TenantStore()
    saved = store.load_tokens("default")
    assert saved["access_token"] == "token123"
    assert saved["client_id"] == "cid"
    assert "expires_at" in saved
