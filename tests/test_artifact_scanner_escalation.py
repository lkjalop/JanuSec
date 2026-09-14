import os

from fastapi.testclient import TestClient

from src.api.server import app

client = TestClient(app)

def test_artifact_scanner_ambiguous_and_high_risk():
    # Craft a batch with:
    #  - Ambiguous risk artifact (lolbin + tunneling + fresh_download) ~ mid risk (escalation / ambiguity band)
    #  - High risk artifact (packed unsigned) to show contrast
    batch = {
        'items': [
            {
                'path': 'C:/Users/user/Downloads/plink.exe',
                'name': 'plink.exe',
                'command_line': 'plink.exe -R 8080:localhost:80',
                'zone_id': 3,  # internet zone => fresh_download
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
        'batch_id': 'ambiguous_vs_high'
    }
    r = client.post('/api/v1/artifacts/analyze_batch', json=batch)
    # Pipeline may be unavailable if optional dependencies missing; skip gracefully
    assert r.status_code == 200, r.text
    data = r.json()
    arts = data.get('report', {}).get('all_artifacts') or []
    # Ensure at least two artifacts returned
    assert len(arts) >= 2
    amb = next(a for a in arts if a['name'] == 'plink.exe')
    high = next(a for a in arts if a['name'] == 'evil.exe')
    # Ambiguous should have tunneling + lolbin + fresh_download factors
    for expect in ('lolbin_misuse','tunneling_utility','fresh_download'):
        assert expect in amb['factors'], amb['factors']
    # Risk in configured ambiguity band (defaults 0.40-0.70); allow small tolerance
    assert 0.3 <= amb['risk'] <= 0.8, amb['risk']
    # High risk should include high_entropy_section or unsigned_binary
    assert any(f in high['factors'] for f in ('high_entropy_section','unsigned_binary')), high['factors']
    assert high['risk'] >= amb['risk']
