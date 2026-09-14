import json
import os
import time
import types
import pytest

from src.integrations.tenant_store import VaultSecretBackend, AzureKeyVaultSecretBackend, FileSecretBackend, MemorySecretBackend, TenantStore
from src.integrations.secret_rotation import rotate_tenant_secret


class DummyResp:
    def __init__(self, status=200, json_data=None, text=''):
        self.status_code = status
        self._json = json_data or {}
        self.text = text
        self.headers = {}

    def json(self):
        return self._json


def test_vault_backend_save_load_delete(monkeypatch, tmp_path):
    # Mock env
    monkeypatch.setenv('VAULT_ADDR', 'http://vault.test')
    monkeypatch.setenv('VAULT_TOKEN', 's.token')
    monkeypatch.setenv('VAULT_KV_MOUNT', 'secret')

    called = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        called['post'] = (url, json)
        return DummyResp(status=200, json_data={'ok': True})

    def fake_get(url, headers=None, timeout=None):
        # Simulate data path response
        if url.endswith('/v1/secret/data/test-key'):
            return DummyResp(status=200, json_data={'data': {'data': {'foo': 'bar'}}})
        return DummyResp(status=404)

    def fake_delete(url, headers=None, timeout=None):
        called['delete'] = url
        return DummyResp(status=204)

    import requests
    monkeypatch.setattr(requests, 'post', fake_post)
    monkeypatch.setattr(requests, 'get', fake_get)
    monkeypatch.setattr(requests, 'delete', fake_delete)

    vb = VaultSecretBackend()
    vb.save('test-key', {'foo': 'bar'})
    got = vb.load('test-key')
    assert got.get('foo') == 'bar'
    vb.delete('test-key')


def test_azure_kv_backend_save_load_delete(monkeypatch):
    monkeypatch.setenv('AZURE_KEY_VAULT_URL', 'https://kv.test')
    monkeypatch.setenv('AZURE_KEY_VAULT_TOKEN', 's.token')

    def fake_put(url, headers=None, json=None, timeout=None):
        return DummyResp(status=200, json_data={'value': json.get('value')})

    def fake_get(url, headers=None, timeout=None):
        return DummyResp(status=200, json_data={'value': 'eyJmb28iOiAiYmFyIn0='})

    def fake_delete(url, headers=None, timeout=None):
        return DummyResp(status=200)

    import requests
    monkeypatch.setattr(requests, 'put', fake_put)
    monkeypatch.setattr(requests, 'get', fake_get)
    monkeypatch.setattr(requests, 'delete', fake_delete)

    az = AzureKeyVaultSecretBackend()
    az.save('test-key', {'foo': 'bar'})
    got = az.load('test-key')
    assert got.get('foo') == 'bar'
    az.delete('test-key')


def test_rotate_helper_memory(monkeypatch, tmp_path):
    monkeypatch.setenv('SECRET_BACKEND', 'memory')
    ts = TenantStore(backend='memory')
    tid = 't-rot'
    ts.save_tokens(tid, {'access_token': 'a', 'refresh_token': 'r', 'expires_at': int(time.time()) + 100})
    out = rotate_tenant_secret(tid)
    assert '_rotated_at' in out
import os
import json
import base64
import tempfile
import requests
import pytest

from src.integrations.tenant_store import VaultSecretBackend, AzureKeyVaultSecretBackend, FileSecretBackend


def test_vault_backend_mock(monkeypatch):
    # configure env for vault
    monkeypatch.setenv('VAULT_ADDR', 'http://vault.local')
    monkeypatch.setenv('VAULT_TOKEN', 'dev-token')
    backend = VaultSecretBackend()
    key = 'tenants/test/tokens'

    class DummyResp:
        def __init__(self, status_code, json_data=None):
            self.status_code = status_code
            self._json = json_data or {}
            self.headers = {}

        def json(self):
            return self._json

    def fake_post(url, headers=None, json=None, timeout=None):
        return DummyResp(200, {'data': {}})

    def fake_get(url, headers=None, timeout=None):
        return DummyResp(200, {'data': {'data': {'a': 1}}})

    monkeypatch.setattr('requests.post', fake_post)
    monkeypatch.setattr('requests.get', fake_get)
    backend.save(key, {'a': 1})
    out = backend.load(key)
    assert out.get('a') == 1


def test_azure_kv_mock(monkeypatch):
    monkeypatch.setenv('AZURE_KEY_VAULT_URL', 'http://akv.local')
    monkeypatch.setenv('AZURE_KEY_VAULT_TOKEN', 'akv-token')
    backend = AzureKeyVaultSecretBackend()
    key = 'tenants/test/tokens'
    encoded = base64.b64encode(json.dumps({'x': 2}).encode('utf-8')).decode('utf-8')

    class DummyResp:
        def __init__(self, status_code, json_data=None):
            self.status_code = status_code
            self._json = json_data or {}
            self.headers = {}

        def json(self):
            return self._json

    def fake_put(url, headers=None, json=None, timeout=None):
        return DummyResp(200, {'value': encoded})

    def fake_get(url, headers=None, timeout=None):
        return DummyResp(200, {'value': encoded})

    monkeypatch.setattr('requests.put', fake_put)
    monkeypatch.setattr('requests.get', fake_get)
    backend.save(key, {'x': 2})
    out = backend.load(key)
    assert out.get('x') == 2
