from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})
import os, json

client = TestClient(app)

def test_rules_summary_and_validation(tmp_path):
    # Create a temporary rules dir with one valid and one invalid rule
    rdir = tmp_path / 'rules'
    rdir.mkdir()
    valid = {
        'id':'rule-1', 'version':'1.0.0', 'name':'Test Rule', 'conditions':[], 'inputs':['events'], 'joins':[], 'mitre':['T1059']
    }
    invalid = {'id':'rule-2','version':'1.0','name':'Bad Rule'}
    (rdir / 'valid.json').write_text(json.dumps(valid))
    (rdir / 'bad.json').write_text(json.dumps(invalid))
    os.environ['RULES_DIR'] = str(rdir)

    r = client.get('/api/v1/rules/summary')
    assert r.status_code == 200
    js = r.json()
    assert js.get('count') == 2

    r2 = client.get('/api/v1/rules/validate')
    assert r2.status_code == 200
    res = r2.json().get('results')
    assert any(r.get('id') == 'rule-1' and r.get('errors') == [] for r in res)
    assert any(r.get('id') == 'rule-2' and len(r.get('errors',[]))>0 for r in res)
