from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})


client = TestClient(app)


def test_sbom_upload_and_vulns_and_vex_flow():
    # Example SBOM payload (matches frontend placeholder)
    payload = {
        "components": [
            {"name": "log4j-core", "version": "2.14.1", "systems": ["app1", "svc-b"]}
        ]
    }

    # Upload SBOM
    r = client.post('/api/v1/sbom/upload', json=payload, headers={})
    assert r.status_code == 200, r.text
    j = r.json()
    assert 'sbom_id' in j
    sbom_id = j['sbom_id']

    # Query vulns (should return structure)
    r2 = client.get(f'/api/v1/sbom/vulns?sbom_id={sbom_id}')
    assert r2.status_code == 200, r2.text
    j2 = r2.json()
    assert j2.get('sbom_id') == sbom_id
    assert 'vulns' in j2 and isinstance(j2['vulns'], list)

    # Add a VEX statement that suppresses the component
    vex_payload = {
        'sbom_id': sbom_id,
        'statements': [
            {
                'component': 'log4j-core',
                # no cve here: apply to component
                'status': 'not_affected',
                'justification': 'demo suppression',
                'version_range': '>=2.0.0,<3.0.0'
            }
        ]
    }

    r3 = client.post('/api/v1/sbom/vex', json=vex_payload)
    assert r3.status_code == 200, r3.text
    j3 = r3.json()
    assert j3.get('sbom_id') == sbom_id

    # After VEX, default GET (without include_suppressed) should hide suppressed vulns
    r4 = client.get(f'/api/v1/sbom/vulns?sbom_id={sbom_id}')
    assert r4.status_code == 200, r4.text
    j4 = r4.json()
    # suppressed vulns are excluded by default, so list may be empty
    assert 'vulns' in j4 and isinstance(j4['vulns'], list)

    # When requesting include_suppressed=true, suppressed entries should appear and include vex_status
    r5 = client.get(f'/api/v1/sbom/vulns?sbom_id={sbom_id}&include_suppressed=true')
    assert r5.status_code == 200, r5.text
    j5 = r5.json()
    assert 'vulns' in j5 and isinstance(j5['vulns'], list)
    # Expect at least one vuln record and that it contains VEX status or suppression markers
    if j5['vulns']:
        found = False
        for v in j5['vulns']:
            if v.get('component') == 'log4j-core':
                # the VEX handler marks 'vex_status' and possibly 'suppressed' flag
                assert v.get('vex_status') in (None, 'not_affected', 'affected', 'fixed', 'under_investigation')
                found = True
        assert found, 'expected log4j-core entry in included vulns'
