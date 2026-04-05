from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})


client = TestClient(app)


def test_tenable_vpr_enriched_in_sbom_flow():
    # Seed Tenable with a VPR score for a test CVE
    cfg = {
        'enabled': True,
        'vpr_map': {'CVE-TEST-1': 9.5}
    }
    hdr = {'x-api-key': 'devkey123'}
    r = client.post('/api/v1/integrations/tenable/config', json=cfg, headers=hdr)
    assert r.status_code == 200, r.text

    sbom = {
        'components': [
            {'name': 'pkgA', 'version': '1.0.0', 'cve': 'CVE-TEST-1', 'cvss_base_score': 7.2}
        ]
    }
    up = client.post('/api/v1/sbom/upload', json=sbom, headers=hdr)
    assert up.status_code == 200, up.text
    sid = up.json()['sbom_id']

    vulns = client.get(f'/api/v1/sbom/vulns?sbom_id={sid}', headers=hdr)
    assert vulns.status_code == 200, vulns.text
    arr = vulns.json().get('vulns') or []
    assert len(arr) >= 1
    v = arr[0]
    # VPR should be present from Tenable stub map
    assert (v.get('vpr') == 9.5) or (v.get('vpr_score') == 9.5)
