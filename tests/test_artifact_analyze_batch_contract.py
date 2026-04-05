import pytest
from fastapi.testclient import TestClient

from api.server import app

client = TestClient(app)

@pytest.mark.parametrize("name, path", [
    ("plink.exe","C:/Users/user/Downloads/plink.exe"),
    ("evil.exe","C:/temp/evil.exe")
])
def test_contract_shape(name, path):
    batch = {
        'items': [
            {
                'path': 'C:/Users/user/Downloads/plink.exe',
                'name': 'plink.exe',
                'command_line': 'plink.exe -R 8080:localhost:80',
                'zone_id': 3,
                'artifact_type': 'executable'
            },
            {
                'path': 'C:/temp/evil.exe',
                'name': 'evil.exe',
                'entropy_high_section': True,
                'signed': False,
                'compile_recent_anomaly': True,
                'artifact_type': 'executable'
            }
        ],
        'batch_id': 'contract_check'
    }
    r = client.post('/api/v1/artifacts/analyze_batch', json=batch)
    assert r.status_code == 200, r.text
    data = r.json()
    report = data.get('report') or {}
    arts = report.get('all_artifacts') or []
    assert len(arts) >= 2
    # Basic field presence checks
    for a in arts:
        for field in ('name','risk','factors','verdict'):
            assert field in a, f"Missing field {field} in artifact {a}"
        assert isinstance(a['factors'], list)
        assert 0.0 <= a['risk'] <= 1.0
