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


def test_compliance_rejects_foreign_tenant_before_reading_or_writing():
    from src.api import compliance_endpoints as module
    request=SimpleNamespace(state=SimpleNamespace(tenant_id='acme',auth=SimpleNamespace(tenant_id='acme')),headers={})
    with pytest.raises(HTTPException) as error:
        asyncio.run(module.remediation_list(status=None,tenant_id='foreign',request=request))
    assert error.value.status_code == 403


def test_legacy_ioc_export_requires_explicit_ownership(monkeypatch):
    from src.api import assessments_endpoints as module
    from src.api.deep_analyze.persistence import REPORT_STORE
    monkeypatch.setitem(REPORT_STORE,'isolation-test',{'assessment_id':'isolation-test','org':'foreign','rows':[{'domain':'private.example'}]})
    request=SimpleNamespace(state=SimpleNamespace(tenant_id='acme',auth=SimpleNamespace(tenant_id='acme')),headers={},query_params={})
    with pytest.raises(HTTPException) as error:
        asyncio.run(module.export_iocs('isolation-test',request))
    assert error.value.status_code == 404


def test_repeated_unclosed_model_tags_preserve_text_without_backtracking():
    from src.security.text_parsing import extract_tag_blocks
    text='<think>' * 100000
    blocks, clean=extract_tag_blocks(text,'think')
    assert blocks==[] and clean==text
    assert extract_tag_blocks('before<THINKING>reason</THINKING>after','thinking',ignore_case=True)==(['reason'],'beforeafter')


def test_model_revisions_reject_moving_tags():
    from src.security.model_revisions import model_revision
    assert len(model_revision('sentence-transformers/all-MiniLM-L6-v2')) == 40
    with pytest.raises(ValueError):
        model_revision('custom/model','main')
    with pytest.raises(ValueError):
        model_revision('unconfigured/model')


def test_vendor_xml_rejects_entity_expansion():
    from src.integrations.qualys_client import ET
    from defusedxml.common import EntitiesForbidden
    with pytest.raises(EntitiesForbidden):
        ET.fromstring('<!DOCTYPE x [<!ENTITY e "expanded">]><x>&e;</x>')


def test_model_artifact_requires_approval_and_detects_changed_bytes(tmp_path, monkeypatch):
    import pickle
    from src.security.model_artifacts import load_approved_model
    artifact=tmp_path/'model.pkl'
    artifact.write_bytes(pickle.dumps({'model':'test'}))
    monkeypatch.delenv('JANUSEC_APPROVED_MODEL_SHA256', raising=False)
    with pytest.raises(RuntimeError):
        load_approved_model(artifact)
    digest=hashlib.sha256(artifact.read_bytes()).hexdigest()
    monkeypatch.setenv('JANUSEC_APPROVED_MODEL_SHA256',json.dumps({str(artifact):digest}))
    assert load_approved_model(artifact)=={'model':'test'}
    artifact.write_bytes(pickle.dumps({'model':'changed'}))
    with pytest.raises(RuntimeError):
        load_approved_model(artifact)


def test_connector_transport_rejects_non_http_and_disables_redirects(monkeypatch):
    from src.security import http_transport as module
    called=[]
    monkeypatch.setattr(module._OPENER,'open',lambda *args,**kwargs: called.append(args))
    for url in ('file:///etc/passwd','ftp://example.com/file','https://user:secret@example.com'):
        with pytest.raises(ValueError):
            module.safe_urlopen(url,allow_private=True)
    assert called==[]
    assert module._NoRedirect().redirect_request(None,None,302,'redirect',{},'https://foreign.example') is None


def test_connector_transport_enforces_public_policy(monkeypatch):
    from src.security import http_transport as module
    monkeypatch.setattr(module,'ssrf_check',lambda url:(False,'private'))
    with pytest.raises(ValueError):
        module.safe_urlopen('https://127.0.0.1/private')


def test_label_edit_cannot_change_another_tenants_row(monkeypatch):
    import sqlite3
    from src.api.labeling_endpoints import edit_label
    from src.db import database
    db=sqlite3.connect(':memory:')
    db.execute('CREATE TABLE decision_labels(id INTEGER, tenant_id TEXT, label TEXT)')
    db.execute("INSERT INTO decision_labels VALUES(1,'foreign','original')")
    async def fetch(sql,*args):
        return [{'id':row[0]} for row in db.execute(sql,args).fetchall()]
    async def execute(sql,*args): db.execute(sql,args)
    monkeypatch.setattr(database,'fetch',fetch)
    monkeypatch.setattr(database,'execute',execute)
    async def body(): return {'label_id':1,'label':'changed'}
    request=SimpleNamespace(json=body,headers={},state=SimpleNamespace(tenant_id='acme',auth=SimpleNamespace(tenant_id='acme')))
    with pytest.raises(HTTPException) as error:
        asyncio.run(edit_label(request))
    assert error.value.status_code == 404
    assert db.execute('SELECT label FROM decision_labels').fetchone()[0]=='original'
    db.close()
