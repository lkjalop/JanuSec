import asyncio
import hashlib
import hmac
import json
from types import SimpleNamespace
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from src.security import crypto_utils


def test_missing_key_never_uses_ephemeral_or_insecure_encryption(monkeypatch):
    monkeypatch.setattr(crypto_utils, 'get_secret', lambda name: None)
    monkeypatch.setenv('ALLOW_INSECURE_FALLBACK', '1')
    with pytest.raises(RuntimeError):
        crypto_utils.encrypt_secret('test credential')


def test_configured_key_survives_module_reload(monkeypatch):
    import importlib
    monkeypatch.setenv('INTEGRATIONS_ENCRYPTION_KEY', Fernet.generate_key().decode())
    encrypted = crypto_utils.encrypt_secret('test credential')
    importlib.reload(crypto_utils)
    assert crypto_utils.decrypt_secret(encrypted) == 'test credential'
    monkeypatch.setenv('INTEGRATIONS_ENCRYPTION_KEY', Fernet.generate_key().decode())
    with pytest.raises(RuntimeError):
        crypto_utils.decrypt_secret(encrypted)


def test_config_encryption_failure_preserves_previous_file(tmp_path, monkeypatch):
    from src.api import integrations_sandbox_endpoints as module
    monkeypatch.chdir(tmp_path)
    target = tmp_path / 'data/integrations/sample.json'
    target.parent.mkdir(parents=True)
    target.write_text('{"previous": true}')
    monkeypatch.setattr(module, 'encrypt_secret', lambda value: (_ for _ in ()).throw(RuntimeError()))
    async def body(): return {'api_key': 'private test credential'}
    with pytest.raises(HTTPException) as error:
        asyncio.run(module.set_integration_config('sample', SimpleNamespace(json=body)))
    assert error.value.status_code == 503
    assert target.read_text() == '{"previous": true}'


def test_config_encrypts_headers_and_callback_secret(tmp_path, monkeypatch):
    from src.api import integrations_sandbox_endpoints as module
    from src.integrations.sandbox.generic_provider import GenericSandboxProvider
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('INTEGRATIONS_ENCRYPTION_KEY', Fernet.generate_key().decode())
    async def body(): return {'api_key': 'test-api', 'webhook_secret': 'test-callback', 'headers': {'Authorization': 'test-header'}}
    asyncio.run(module.set_integration_config('sample', SimpleNamespace(json=body)))
    text = (tmp_path / 'data/integrations/sample.json').read_text()
    assert all(secret not in text for secret in ('test-api', 'test-callback', 'test-header'))
    assert GenericSandboxProvider('sample').headers['Authorization'] == 'test-header'


def test_webhook_missing_secret_rejected_and_signed_secret_accepted(tmp_path, monkeypatch):
    from src.api import sandbox_webhooks as module
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('INTEGRATIONS_ENCRYPTION_KEY', Fernet.generate_key().decode())
    recorded=[]
    monkeypatch.setattr(module, 'record_memory_job', recorded.append)
    app=FastAPI(); app.include_router(module.router)
    client=TestClient(app)
    body=json.dumps({'task_id':'test', 'verdict':'suspicious'}).encode()
    assert client.post('/api/v1/sandbox/webhook/sample', content=body).status_code == 503
    target=tmp_path/'data/integrations/sample.json'; target.parent.mkdir(parents=True)
    target.write_text(json.dumps({'webhook_secret':crypto_utils.encrypt_secret('callback-test'), '_webhook_secret_encrypted':True}))
    assert client.post('/api/v1/sandbox/webhook/sample', content=body).status_code == 403
    signature=hmac.new(b'callback-test',body,hashlib.sha256).hexdigest()
    assert client.post('/api/v1/sandbox/webhook/sample', content=body,headers={'X-Sandbox-Signature':signature}).status_code == 200
    assert len(recorded)==1


def test_uploaded_local_paths_do_not_read_server_files(tmp_path, monkeypatch):
    from src.analysis.offline_workbook_assessment import _read_local_attachment_bytes, _read_local_text
    secret=tmp_path/'private.txt'; secret.write_text('private server data')
    monkeypatch.delenv('JANUSEC_OFFLINE_ATTACHMENT_READS', raising=False)
    assert _read_local_attachment_bytes({'attachment_path':str(secret)}) is None
    assert _read_local_text(str(secret)) == ''


def test_expansion_cache_does_not_alias_identifiers(tmp_path, monkeypatch):
    from src.analysis import expand_engine
    monkeypatch.setattr(expand_engine,'EXPAND_CACHE_DIR',str(tmp_path))
    assert expand_engine.get_expand_cache_path('a/b','t') != expand_engine.get_expand_cache_path('a_b','t')
