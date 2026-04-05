import os, sys, importlib, time
sys.path.insert(0, r'd:\AI\Threat_thy_sniffer')
from types import SimpleNamespace
os.environ['THREAT_INTEL_DB_PATH'] = r'd:\AI\Threat_thy_sniffer\tmp\ti.sqlite'
os.environ['CERT_CHECK_TTL_SEC'] = '3600'
os.environ['CERT_CT_API_URL'] = 'https://ct.example'
os.environ['CERT_OCSP_API_URL'] = 'https://ocsp.example'
os.environ['CERT_CHECK_WEBHOOK_URL'] = 'https://webhook.example/hit'
os.environ['CERT_CHECK_WEBHOOK_SECRET'] = 'secret123'
os.environ['CERT_CHECK_BATCH_SIZE'] = '2'
os.environ['CERT_CHECK_BATCH_INTERVAL_SEC'] = '1'
os.environ['CERT_CHECK_RATE_PER_MIN'] = '100'
import src.integrations.cert_checks as cc
importlib.reload(cc)

calls = {'get':[], 'post':[]}
class DummyResp:
    def __init__(self, status_code=200, json_data=None, headers=None):
        self.status_code = status_code
        self._json = json_data or {}
        self.headers = headers or {'content-type':'application/json'}
    def json(self):
        return self._json

def fake_get(url, timeout=5.0):
    calls['get'].append(url)
    if '/ct/' in url:
        suspicious = 'flag' in url
        return DummyResp(200, {'suspicious': suspicious, 'detail': 'ct-mock'})
    if '/ocsp/' in url:
        st = 'revoked' if url.endswith('rev') else 'good'
        return DummyResp(200, {'status': st, 'detail': 'ocsp-mock'})
    return DummyResp(404, {})

def fake_post(url, data=None, headers=None, timeout=5.0):
    calls['post'].append({'url': url, 'data': data, 'headers': headers})
    return DummyResp(200, {'ok': True})

cc.httpx = SimpleNamespace(get=fake_get, post=fake_post)

cc.queue_cert_check('flag-cert-123')
cc.queue_cert_check('normal-cert-rev')
cc.start_worker(background=False)
cc.start_worker(background=False)
cc.flush_now()

print('calls:', calls)
print('pending:', cc.get_pending_webhook_batches())
print('db entries: ', cc.get_cert_check('flag-cert-123'), cc.get_cert_check('normal-cert-rev'))
