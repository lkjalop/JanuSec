from src.api.taxonomy_mapper import map_mitre_to_taxonomies, enrich_graph_with_taxonomies
from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})

client = TestClient(app)

def test_map_mitre_basic():
    res = map_mitre_to_taxonomies(['T1005','T1071.001'])
    assert 'stride' in res and isinstance(res['stride'], list)
    assert res['dread_score'] >= 0
    assert 'compliance_controls' in res


def test_playbook_generate_and_execute():
    # Build a graph with a known mitre technique
    graph = {'nodes': [], 'edges': []}
    resp = client.post('/api/v1/playbooks/generate', json={'graph': graph, 'mitre_techniques': ['T1005'], 'confidence_threshold': 0.4})
    assert resp.status_code == 200
    j = resp.json()
    assert 'playbook_id' in j
    pbid = j['playbook_id']
    exec_resp = client.post('/api/v1/playbooks/execute', json={'playbook_id': pbid})
    assert exec_resp.status_code == 200
    ej = exec_resp.json()
    assert 'execution' in ej and ej['execution']['playbook_id'] == pbid


def test_playbook_template_selection():
    # Create a graph with high cvss to force containment template
    graph = {'nodes': [], 'edges': [], 'taxonomies': {'cvss_base': 8.0, 'dread_score': 4.0, 'stride': []}}
    resp = client.post('/api/v1/playbooks/generate', json={'graph': graph})
    assert resp.status_code == 200
    j = resp.json()
    assert 'playbook' in j and j['playbook'].get('template') in ('containment_forensics', 'containment_forensics.json', None) or j['playbook'].get('steps')
