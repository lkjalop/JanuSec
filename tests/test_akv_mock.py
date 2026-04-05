import os
import base64
import json
import pytest
from unittest import mock

from src.integrations.tenant_store import AzureKeyVaultSecretBackend, SecretBackendError

def test_akv_backend_mock(monkeypatch):
    # Ensure env vars are present for constructor to proceed
    monkeypatch.setenv('AZURE_KEY_VAULT_URL', 'https://example.vault.azure.net')
    monkeypatch.setenv('AZURE_KEY_VAULT_TOKEN', 'fake-token')
    called = {}

    class DummyResp:
        def __init__(self, status_code, json_data=None, text=''):
            self.status_code = status_code
            self._json = json_data or {}
            self.text = text
        def json(self):
            return self._json

    def fake_put(url, headers=None, json=None, timeout=None):
        called['put'] = (url, headers, json)
        return DummyResp(200, {'value': json.get('value')})

    def fake_get(url, headers=None, timeout=None):
        called['get'] = (url, headers)
        # return a base64-encoded payload
        stored = called.get('stored_value')
        if stored:
            return DummyResp(200, {'value': stored})
        return DummyResp(404, {})

    def fake_delete(url, headers=None, timeout=None):
        called['delete'] = (url, headers)
        return DummyResp(204, {})

    monkeypatch.setattr('requests.put', fake_put)
    monkeypatch.setattr('requests.get', fake_get)
    monkeypatch.setattr('requests.delete', fake_delete)

    akv = AzureKeyVaultSecretBackend()
    key = 'tenants/test-tenant/tokens'
    payload = {'access_token': 'ax', 'refresh_token': 'rf', 'expires_at': 12345}
    # Save should call put
    akv.save(key, payload)
    # The fake put stored encoded value in called['put']
    encoded = called['put'][2]['value']
    called['stored_value'] = encoded
    # Load should decode
    loaded = akv.load(key)
    assert loaded == payload
    # Delete should not raise
    akv.delete(key)

