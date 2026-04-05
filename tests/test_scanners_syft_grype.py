import os
import json
import pytest

API_KEY = os.environ.get('TEST_API_KEY', 'devkey123')

@pytest.fixture(scope='module')
def client():
    os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
    os.environ.setdefault('PLATFORM_LITE_INIT', '1')
    os.environ.setdefault('DISABLE_DB', '1')
    from src.api.app import app
    from fastapi.testclient import TestClient
    return TestClient(app)


def _h():
    return { 'x-api-key': API_KEY, 'Content-Type': 'application/json' }


def test_syft_relationships_wiring_via_sbom_upload(client):
    # Directly upload a Syft-like SBOM with relationships using 'dependsOn'
    payload = {
        'sbom_id': 'syft-test',
        'components': [
            {'name': 'app', 'version': '1.0.0'},
            {'name': 'libA', 'version': '1.2.3'},
        ],
        'relationships': [
            {'ref': 'app', 'dependsOn': ['libA']}
        ]
    }
    r = client.post('/api/v1/sbom/upload', headers=_h(), data=json.dumps(payload))
    assert r.status_code == 200
    # Validate HopGraph edge exists: package:app:1.0.0 -> package:libA:1.2.3 depends_on
    from src.graph.hopgraph import GLOBAL_HOPGRAPH
    src_id = 'package:app:1.0.0'
    dst_id = 'package:libA:1.2.3'
    edges = GLOBAL_HOPGRAPH.adj.get(src_id, [])
    assert any((e[0] == dst_id and e[1] == 'depends_on') for e in edges)


def test_grype_trigger_forwards_to_sbom(client, monkeypatch):
    from src.collectors.scanners.grype_connector import GrypeConnector
    async def fake_run_scan(self, target: str):
        return {
            'sbom_id': 'grype-test',
            'components': [
                {'name': 'struts', 'version': '2.5.10', 'cve': 'CVE-2017-5638', 'cvss_base_score': 10.0}
            ]
        }
    monkeypatch.setattr(GrypeConnector, 'run_scan', fake_run_scan)
    r = client.post('/api/v1/scanners/grype/trigger', headers=_h(), data=json.dumps({'target': 'dummy'}))
    assert r.status_code == 200
    j = r.json(); assert j['status'] == 'scheduled'
    # SBOM endpoint returns counts; ensure it processed the component
    sbres = j.get('sbom_result') or {}
    assert sbres.get('components', 0) >= 1
