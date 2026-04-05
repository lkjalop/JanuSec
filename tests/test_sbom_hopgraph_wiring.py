import os
import time
from fastapi.testclient import TestClient

# Ensure deterministic/shared state in test mode
os.environ.setdefault('TEST_HELPERS_ENABLED', '1')
os.environ.setdefault('FAST_TEST_MODE', '1')

from src.api.app import create_app
app = create_app({'mode': 'test'})
from src.graph.hopgraph import HopGraph


def _reset_hopgraph():
    # Attach a fresh HopGraph instance so counts are isolated per test
    app.GLOBAL_HOPGRAPH = HopGraph()


def _post_sbom(client, payload):
    headers = {'x-api-key': os.getenv('API_KEY', 'devkey123')}
    return client.post('/api/v1/sbom/upload', json=payload, headers=headers)


def _get_hopgraph():
    # After TestClient startup, app.state.hopgraph should be set
    return getattr(app.state, 'hopgraph', getattr(app, 'GLOBAL_HOPGRAPH', None))


def test_component_dependencies_produce_package_edges():
    _reset_hopgraph()
    with TestClient(app) as client:
        payload = {
            'sbom_id': 'sbom-test-1',
            'components': [
                {'name': 'A', 'version': '1.0.0', 'dependencies': {'B': '^1.0.0', 'C': '~2.0.0'}},
                {'name': 'B', 'version': '1.0.0'},
                {'name': 'C', 'version': '2.0.1'}
            ]
        }
        r = _post_sbom(client, payload)
        assert r.status_code == 200, r.text
        hg = _get_hopgraph()
        assert hg is not None
        # Allow a brief moment for any async drains, though add_edge is synchronous in this config
        time.sleep(0.05)
        # Validate nodes present
        nodes = hg.nodes
        assert f'package:A:1.0.0' in nodes
        assert f'package:B:1.0.0' in nodes
        assert f'package:C:2.0.1' in nodes
        # Validate depends_on edges from A to B and A to C
        adj = hg.adj.get('package:A:1.0.0', [])
        dests = {(dst, et) for (dst, et, *_rest) in adj}
        assert ('package:B:1.0.0', 'depends_on') in dests
        assert ('package:C:2.0.1', 'depends_on') in dests


def test_cyclonedx_top_level_dependencies_wire_edges():
    _reset_hopgraph()
    with TestClient(app) as client:
        payload = {
            'sbom_id': 'sbom-test-2',
            'components': [
                {'name': 'core', 'version': '3.2.0'},
                {'name': 'util', 'version': '1.5.1'}
            ],
            'dependencies': [
                {'ref': 'core', 'dependsOn': ['util']}
            ]
        }
        r = _post_sbom(client, payload)
        assert r.status_code == 200, r.text
        hg = _get_hopgraph()
        assert hg is not None
        time.sleep(0.05)
        # Nodes
        assert 'package:core:3.2.0' in hg.nodes
        assert 'package:util:1.5.1' in hg.nodes
        # Edge core -> util
        adj = hg.adj.get('package:core:3.2.0', [])
        dests = {(dst, et) for (dst, et, *_rest) in adj}
        assert ('package:util:1.5.1', 'depends_on') in dests
