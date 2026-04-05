import asyncio
import json
import os
import time

import pytest

import os

from src.integrations.ms_graph_connector import MicrosoftGraphConnector
from src.integrations.tenant_store import TenantStore

# Use in-memory tenant store for tests
os.environ.setdefault('SECRET_BACKEND', 'memory')


class _MockResp:
    def __init__(self, status_code: int, payload: dict):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


def _patch_session_get(monkeypatch, payload):
    def _get(self, url, headers=None, params=None, timeout=None):
        return _MockResp(200, payload)

    monkeypatch.setattr('requests.sessions.Session.get', _get)


def test_connect_uses_tenant_tokens():
    store = TenantStore(backend='memory')
    tenant = 'test-tenant-connect'
    sample = {
        'access_token': 'token123',
        'expires_at': int(time.time()) + 3600,
        'client_id': 'cid',
        'client_secret': 'csecret'
    }
    store.save_tokens(tenant, sample)

    conn = MicrosoftGraphConnector(tenant_id=tenant)
    # Should not raise
    asyncio.run(conn.connect())
    assert conn._access_token == 'token123'


def test_fetch_since_returns_events_and_cursor(monkeypatch):
    store = TenantStore(backend='memory')
    tenant = 'test-tenant-fetch'
    # Use far-future expiry so connector will accept token
    with open(os.path.join(os.path.dirname(__file__), 'fixtures', 'sample_msgraph_token.json'), 'r', encoding='utf-8') as fh:
        sample = json.load(fh)
    store.save_tokens(tenant, sample)

    # Prepare a Graph-like signIns response
    now_iso = '2024-01-01T00:00:00Z'
    payload = {'value': [{'id': '1', 'createdDateTime': now_iso}], '@odata.nextLink': None}
    _patch_session_get(monkeypatch, payload)

    conn = MicrosoftGraphConnector(tenant_id=tenant)
    events, cursor = asyncio.run(conn.fetch_since(None, limit=10))
    assert isinstance(events, list)
    assert len(events) == 1
    assert events[0]['raw']['id'] == '1'
    assert cursor == now_iso
