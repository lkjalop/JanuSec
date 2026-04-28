import os, json, sqlite3, time
os.environ['PLATFORM_LITE_INIT'] = '1'
from fastapi.testclient import TestClient
from src.api.app import app
from src.api.integrations_endpoints import _dispatch_audit


def _read_audit(aid):
    db = os.getenv('DISPATCH_AUDIT_DB', os.path.join(os.path.dirname(__file__), '..', 'data', 'dispatch_audit.db'))
    conn = sqlite3.connect(db)
    try:
        cur = conn.cursor()
        cur.execute('SELECT id, tenant_id, endpoint, status, attempts FROM dispatch_audit WHERE id=?', (aid,))
        return cur.fetchone()
    finally:
        conn.close()


def test_dispatch_audit_recorded():
    client = TestClient(app)
    os.environ['API_KEYS_JSON'] = json.dumps([{'key':'testkey123','scopes':['*']}])
    payload = {'ask': {'api': {'endpoint': '/api/v1/identity/pull'}, 'users': ['alice']}, 'dispatch_id': 'test-dispatch-1'}
    r = client.post('/api/v1/gaps/dispatch', json=payload, headers={'X-API-Key': 'testkey123'})
    assert r.status_code == 200
    # allow small delay for audit write
    time.sleep(0.1)
    row = _read_audit('test-dispatch-1')
    assert row is not None
    assert row[0] == 'test-dispatch-1'


def _admin_headers():
    os.environ['API_KEYS_JSON'] = json.dumps([{'key': 'testkey123', 'scopes': ['*']}])
    return {'X-API-Key': 'testkey123'}


def test_dispatch_notify_rejects_unknown_role():
    client = TestClient(app)
    r = client.post(
        '/api/v1/dispatch/notify',
        json={'assessment_id': 'assessment-1', 'role': 'not_a_role'},
        headers=_admin_headers(),
    )
    assert r.status_code == 400
    assert r.json().get('detail') == 'unknown_role'


def test_dispatch_notify_requires_assessment_id():
    client = TestClient(app)
    r = client.post(
        '/api/v1/dispatch/notify',
        json={'role': 'soc_analyst'},
        headers=_admin_headers(),
    )
    assert r.status_code == 400
    assert r.json().get('detail') == 'missing_assessment_id'


def test_dispatch_notify_logs_change_management_flag_in_audit():
    client = TestClient(app)
    _dispatch_audit.clear()
    r = client.post(
        '/api/v1/dispatch/notify',
        json={
            'assessment_id': 'assessment-test-cab',
            'role': 'soc_analyst',
            'requires_change_management': True,
        },
        headers=_admin_headers(),
    )
    assert r.status_code == 200
    payload = r.json()
    assert payload.get('requires_change_management') is True

    audit = client.get('/api/v1/dispatch/audit', headers=_admin_headers())
    assert audit.status_code == 200
    entries = audit.json().get('entries', [])
    assert entries, 'Expected at least one dispatch audit entry'
    last = entries[-1]
    assert last.get('assessment_id') == 'assessment-test-cab'
    assert last.get('role') == 'soc_analyst'
    assert last.get('requires_change_management') is True
