import os
import time
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from src.api.server import app
from src.integrations.tenant_store import TenantStore
from src.integrations.msgraph_connector import MSGraphConnector


def test_refresh_on_401(monkeypatch, tmp_path):
    # Prepare a tenant with expired token and a refresh token
    # Redirect STORE_DIR for isolation in tests
    import src.integrations.tenant_store as tsmod
    tsmod.STORE_DIR = str(tmp_path / 'tenant_store')
    import os as _os
    _os.makedirs(tsmod.STORE_DIR, exist_ok=True)
    store = TenantStore()
    tenant_id = 'tenant-refresh'
    now = int(time.time())
    tokens = {'access_token': 'old', 'refresh_token': 'ref', 'expires_at': now - 10}
    store.save_tokens(tenant_id, tokens)

    # Mock MSGraphConnector.refresh_token to return a new access token
    worker_module = __import__('src.integrations.polling_worker', fromlist=['MailPollingWorker'])
    MailPollingWorker = worker_module.MailPollingWorker
    # Create a worker that will call _ensure_valid_token
    w = MailPollingWorker(tenant_id=tenant_id, provider='msgraph')
    # Force tokens load from our TenantStore path
    w.store = store
    # Replace connector with a mock that returns refreshed tokens
    mock_conn = MagicMock()
    mock_conn.refresh_token.return_value = {'access_token': 'new', 'expires_in': 3600, 'refresh_token': 'ref2'}
    mock_conn.client_id = 'cid'
    mock_conn.client_secret = 'csecret'
    mock_conn.redirect_uri = None
    w.conn = mock_conn
    refreshed = w._ensure_valid_token(tokens)
    assert refreshed.get('access_token') == 'new'
    # token saved back to store
    saved = store.load_tokens(tenant_id)
    assert saved.get('access_token') == 'new'
