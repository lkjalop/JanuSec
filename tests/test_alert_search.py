import json
import os
import time

from fastapi.testclient import TestClient

from src.api.server import _ALERT_RING, _ALERT_RING_LOCK, app

API_KEY_ENV = 'ALERTS_API_KEYS'

def _set_api_key():
    os.environ[API_KEY_ENV] = 'testkey'

client = TestClient(app)

class TestAlertSearch:
    def setup_method(self):
        _set_api_key()
        with _ALERT_RING_LOCK:
            _ALERT_RING.clear()
        # Insert synthetic alerts through ring + store append
        from src.live import alert_store
        now = time.time()
        for i in range(5):
            rec = {
                'id': f'a{i}', 'ts': now + i, 'host': 'h1' if i<3 else 'h2',
                'verdict': 'ALERT', 'score': 0.9 - i*0.05, 'rules': ['lolbin_misuse'],
                'dest_ip': '1.1.1.%d' % i
            }
            alert_store.append(rec)
            with _ALERT_RING_LOCK:
                _ALERT_RING.append(rec)
        # ensure ordering
    def test_filter_host(self):
        r = client.get('/api/v1/alerts/search', headers={'X-API-Key':'testkey'}, params={'host':'h1'})
        assert r.status_code == 200
        data = r.json()
        assert all(a['host']=='h1' for a in data['alerts'])
        assert data['returned'] == 3
    def test_pagination(self):
        r = client.get('/api/v1/alerts/search', headers={'X-API-Key':'testkey'}, params={'limit':2,'offset':1})
        assert r.status_code == 200
        d = r.json()
        assert d['returned'] == 2
        # second page different
        r2 = client.get('/api/v1/alerts/search', headers={'X-API-Key':'testkey'}, params={'limit':2,'offset':3})
        assert r2.status_code == 200
        d2 = r2.json()
        ids_page1 = {a['id'] for a in d['alerts']}
        ids_page2 = {a['id'] for a in d2['alerts']}
        assert not ids_page1 & ids_page2
