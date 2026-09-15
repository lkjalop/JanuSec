import os, importlib, json, time
from types import SimpleNamespace
# set env like test fixture
os.environ['THREAT_INTEL_DB_PATH'] = 'data/test_ti.sqlite'
os.environ['CERT_CHECK_TTL_SEC'] = '3600'
os.environ['CERT_CT_API_URL'] = 'https://ct.example'
os.environ['CERT_OCSP_API_URL'] = 'https://ocsp.example'
os.environ['CERT_CHECK_WEBHOOK_URL'] = 'https://webhook.example/fail-first'
os.environ['CERT_CHECK_WEBHOOK_SECRET'] = 'secret123'
os.environ['CERT_CHECK_BATCH_SIZE'] = '1'
os.environ['CERT_CHECK_BATCH_INTERVAL_SEC'] = '1'
os.environ['CERT_CHECK_RATE_PER_MIN'] = '100'
os.environ['CERT_CHECK_WEBHOOK_MAX_ATTEMPTS'] = '3'
os.environ['ADMIN_API_KEY'] = 'adminkey'

import src.integrations.cert_checks as cc
importlib.reload(cc)

calls = []
def fake_post(url, content=None, headers=None, timeout=5.0):
    print('fake_post called', url)
    calls.append({'url':url,'content':content,'headers':headers})
    return SimpleNamespace(status_code=200)

cc.httpx = SimpleNamespace(get=lambda url, timeout=5.0: SimpleNamespace(status_code=200, json=lambda: {}), post=fake_post)

payload = json.dumps({'findings':[{'certfp':'flag-cert-flush-123','status':'suspicious','details':'x','ts':int(time.time())}], 'count':1})
cc._persist_failed_batch(payload, 1, 'simulated_error')

print('pending before flush (db-based):')
import sqlite3
conn = sqlite3.connect(os.environ['THREAT_INTEL_DB_PATH'])
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM webhook_batches")
print(cur.fetchone())
conn.close()

print('calling flush_now')
cc.flush_now()
print('calls:', calls)
print('TEST_CAPTURE_PRIMARY_POST (module-level):', cc.__dict__.get('_TEST_CAPTURE_PRIMARY_POST'))
print('TEST_CAPTURE_RETRY_POSTS (module-level):', cc.__dict__.get('_TEST_CAPTURE_RETRY_POSTS'))
