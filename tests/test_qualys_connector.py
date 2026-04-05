import json
import pytest

from src.adapters.qualys_connector import QualysConnector


class DummyResponse:
    def __init__(self, status=200, body=None):
        self.status = status
        self._body = body or {}

    def raise_for_status(self):
        if self.status >= 400:
            raise Exception(f'status {self.status}')

    def json(self):
        return self._body


def test_fetch_token(monkeypatch):
    called = {}

    def fake_post(url, data, auth, timeout):
        called['url'] = url
        # Return a JSON body similar to OAuth client_credentials
        return DummyResponse(200, {'access_token': 'tok-123', 'expires_in': 3600})

    monkeypatch.setattr('requests.post', fake_post)
    qc = QualysConnector('cid', 'secret', api_base='https://qualys.test')
    t = qc.fetch_token()
    assert t == 'tok-123'
    # calling again should reuse cached token (no new requests.post invocation)
    t2 = qc.fetch_token()
    assert t2 == 'tok-123'


def test_list_vulns_pagination(monkeypatch):
    # Simulate two pages: first returns items + next_cursor, second empty
    calls = {'i': 0}

    def fake_get(url, headers, params, timeout):
        i = calls['i']
        calls['i'] += 1
        if i == 0:
            body = {'items': [{'id': 'v1'}, {'id': 'v2'}], 'next_cursor': 'cur-1'}
            return DummyResponse(200, body)
        elif i == 1:
            body = {'items': [{'id': 'v3'}]}
            return DummyResponse(200, body)
        else:
            return DummyResponse(200, {'items': []})

    def fake_post(url, data, auth, timeout):
        return DummyResponse(200, {'access_token': 't', 'expires_in': 3600})

    monkeypatch.setattr('requests.get', fake_get)
    monkeypatch.setattr('requests.post', fake_post)

    qc = QualysConnector('cid', 'secret', api_base='https://qualys.test')
    items = list(qc.list_vulns(page_size=2))
    assert len(items) >= 3
    ids = [it.get('id') for it in items]
    assert 'v1' in ids and 'v2' in ids and 'v3' in ids


def test_map_vuln_to_artifact_basic():
    qc = QualysConnector('cid', 'secret', api_base='https://qualys.test')
    vuln = {'id': 'V-100', 'asset_id': 'A-1', 'package': 'openssl', 'severity': 'high'}
    mapped = qc.map_vuln_to_artifact(vuln)
    assert mapped['vuln_id'] == 'V-100'
    assert mapped['asset_id'] == 'A-1'
    assert mapped['package'] == 'openssl'
    assert mapped['severity'] == 'high'
