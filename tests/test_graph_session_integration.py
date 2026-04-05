from src.api.app import app
import json


def get_client():
    from fastapi.testclient import TestClient
    try:
        from src.api.app import create_app
        _app = create_app({'mode': 'test'}) or app
    except Exception:
        _app = app
    return TestClient(_app)

def default_test_headers():
    return {'x-api-key': 'devkey123'}


def test_upload_creates_sessions_and_builds_graph():
    # Upload a small JSON payload as file
    data = json.dumps([{'user':'alice','host':'host1','ip':'10.0.0.1','domain':'example.com'}])
    files = {'files': ('test.json', data, 'application/json')}
    headers = default_test_headers()
    headers['X-Correlation-Analyze'] = '1'
    r = get_client().post('/api/v1/upload/files', files=files, headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert 'session_ids' in body and isinstance(body['session_ids'], list) and len(body['session_ids'])>0
    sid = body['session_ids'][0]

    # Build graph using persisted session id
    resp = get_client().post('/api/v1/graph/session/build', json={'session_ids':[sid], 'ewma': False}, headers=default_test_headers())
    assert resp.status_code == 200, resp.text
    j = resp.json()
    assert 'graph' in j and 'nodes' in j['graph'] and 'edges' in j['graph']
    # Expect at least one session node and one entity node
    node_types = set(n.get('type') for n in j['graph']['nodes'])
    assert 'session' in node_types
    assert any(n for n in j['graph']['nodes'] if n.get('type')!='session')


def test_graph_nodes_have_evidence_counts():
    # reuse earlier upload and session
    data = json.dumps([{'user':'bob','host':'host2','ip':'10.0.0.2','domain':'example.org'}])
    files = {'files': ('test2.json', data, 'application/json')}
    headers = default_test_headers(); headers['X-Correlation-Analyze'] = '1'
    r = get_client().post('/api/v1/upload/files', files=files, headers=headers)
    assert r.status_code == 200
    body = r.json()
    sid = body.get('session_ids', [None])[0]
    resp = get_client().post('/api/v1/graph/session/build', json={'session_ids':[sid], 'ewma': False}, headers=default_test_headers())
    assert resp.status_code == 200
    j = resp.json()
    nodes = j['graph']['nodes']
    # Find an entity node and ensure evidence_count present
    ent_nodes = [n for n in nodes if not n.get('id','').startswith('session:')]
    assert ent_nodes and any(n.get('evidence_count',0) > 0 for n in ent_nodes)


def test_playbook_execution_dispatch():
    # generate a playbook and execute it via endpoint
    graph = {'nodes': [], 'edges': [], 'taxonomies': {'cvss_base': 8.0}}
    r = get_client().post('/api/v1/playbooks/generate', json={'graph': graph})
    assert r.status_code == 200
    pbid = r.json()['playbook_id']
    exec_resp = get_client().post('/api/v1/playbooks/execute', json={'playbook_id': pbid})
    assert exec_resp.status_code == 200
    ej = exec_resp.json()
    assert 'execution' in ej and isinstance(ej['execution'], dict)
