import os
import json
import tempfile
from fastapi.testclient import TestClient
from src.api.app import create_app

app = create_app({'mode':'test'})
client = TestClient(app)


def test_missing_tenant_header_is_rejected():
    # Ensure env defaults to strict mode for this test
    os.environ.pop('MAPPINGS_ALLOW_DEFAULT_TENANT', None)
    os.environ['MAPPINGS_ENFORCE_STRICT'] = '1'
    payload = { 'mapping': {'user':'u'}, 'rows': [{'u':'alice'}] }
    r = client.post('/api/v1/mappings/preview', json=payload)
    assert r.status_code == 400
    assert 'tenant' in r.json().get('detail','').lower()


def test_preview_fallback_and_save_with_tenant(tmp_path):
    # allow default tenant for broader compatibility in this test
    os.environ['MAPPINGS_ALLOW_DEFAULT_TENANT'] = '1'
    # create a mapping and preview with tenant header
    mapping = { 'user': 'username', 'ip': 'src_ip' }
    rows = [ {'username':'bob','src_ip':'1.2.3.4'}, {'username':'eve','src_ip':'5.6.7.8'} ]
    r = client.post('/api/v1/mappings/preview', json={'mapping':mapping, 'rows': rows}, headers={'x-tenant-id':'acme'})
    assert r.status_code == 200
    j = r.json()
    assert 'results' in j or 'mapping' in j
    # now save the mapping under tenant
    name = 'test-preset'
    r2 = client.post(f'/api/v1/mappings/{name}', json={'mapping':mapping, 'headers':['username','src_ip']}, headers={'x-tenant-id':'acme'})
    assert r2.status_code == 200
    j2 = r2.json()
    assert j2.get('saved') == name
    assert j2.get('tenant') == 'acme'
    # list presets for tenant
    r3 = client.get('/api/v1/mappings/', headers={'x-tenant-id':'acme'})
    assert r3.status_code == 200
    assert name in r3.json().get('mappings', [])

