import asyncio
import json
import os

import pytest

from src.integrations.proofpoint_tap import ProofpointTAPConnector
from src.integrations.tenant_store import TenantStore


class _MockResp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload
        self.text = json.dumps(payload)

    def json(self):
        return self._payload
    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f'Status {self.status_code}: {self.text}')


def test_proofpoint_fetch_since(monkeypatch, tmp_path):
    import os
    os.environ.setdefault('SECRET_BACKEND', 'memory')
    store = TenantStore(backend='memory')
    tenant = 'pp-test'
    store.save_tokens(tenant, {'proofpoint': {'api_key': 'fake-key'}})

    payload = {'data': [{'threatTime': '2025-01-01T00:00:00Z', 'messageID': '<m1>'}], 'next': None}

    def _get(self, url, params=None, headers=None, timeout=None):
        return _MockResp(200, payload)

    monkeypatch.setattr('requests.sessions.Session.get', _get)

    conn = ProofpointTAPConnector(tenant_id=tenant)
    events, cursor = asyncio.run(conn.fetch_since(None, limit=10))
    assert isinstance(events, list)
    assert len(events) == 1
    assert cursor is None or isinstance(cursor, str)
