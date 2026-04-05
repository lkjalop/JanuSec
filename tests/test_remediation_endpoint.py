import os
import pytest
from fastapi.testclient import TestClient

os.environ.setdefault('PLATFORM_LITE_INIT','1')  # lighten startup for test speed
os.environ.setdefault('STRICT_API_KEY_ENFORCEMENT','0')

from src.api.app import create_app
app = create_app({'mode': 'test'})

client = TestClient(app)

def test_remediation_suggest_basic_chain():
    path = 'alice@example.com->host123->a3f5d2b4c6e7f8a9b0d1c2e3f4a5b6c7'
    r = client.get('/api/v1/remediation/suggest', params={'path': path})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data['path'] == path
    assert data['severity'] in {'high','critical','medium','low'}
    # Expect types inferred: email, host, file_hash
    assert data['types'][0] == 'email'
    assert 'file_hash' in data['types']
    assert len(data['actions']) > 0
    assert data['suggested_count'] == len(data['actions'])

def test_remediation_suggest_user_host_filehash():
    path = 'user42->hostA->9f86d081884c7d659a2feaa0c55ad015'
    r = client.get('/api/v1/remediation/suggest', params={'path': path})
    assert r.status_code == 200
    js = r.json()
    assert js['types'][0] in {'user','host'}  # user42 should map to user
    assert 'file_hash' in js['types']
    assert any('Quarantine file' in a for a in js['actions'])
    assert js['severity'] in {'low','medium','high','critical'}

def test_remediation_empty_path_error():
    r = client.get('/api/v1/remediation/suggest', params={'path': ''})
    assert r.status_code == 400
    assert 'empty_path' in r.text
