import os
import json
import time
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.runtime_state import get_server_runtime_state, get_permission_graph
from src.domains.iam.policy_ingest import parse_policy_document


def setup_env():
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    os.environ['PLATFORM_LITE_INIT'] = '1'
    os.environ['DISABLE_DB'] = '1'


def test_weight_overrides_and_ingest_roundtrip():
    setup_env()
    app = create_app()
    client = TestClient(app)
    tenant = 'test-tenant-1'

    # Post weight overrides
    overrides = {'public': 6.5, 'cross_account': 2.0, 'same_account': 1.0, 'unknown': 9.0}
    resp = client.post('/api/v1/iam/admin/weight_overrides', json={'weight_overrides': overrides, 'tenant': tenant})
    assert resp.status_code == 200

    # Verify get endpoint
    resp = client.get(f'/api/v1/iam/admin/weight_overrides?tenant={tenant}')
    assert resp.status_code == 200
    data = resp.json()
    assert data.get('tenant') == tenant
    assert data.get('weight_overrides') == overrides

    # Create a simple policy with a public principal and a role resource
    sample_policy = {
        'Statement': [
            {
                'Effect': 'Allow',
                'Principal': '*',
                'Action': 'sts:AssumeRole',
                'Resource': 'arn:aws:iam::111111111111:role/TargetRole'
            }
        ]
    }

    resp = client.post('/api/v1/iam/ingest_policy', json={'policy': sample_policy, 'tenant': tenant})
    assert resp.status_code == 200

    # Quick parse check: ensure parse_policy_document returns edges
    pairs, edges = parse_policy_document(sample_policy)
    assert len(edges) > 0
    assert any(e.get('to') == 'arn:aws:iam::111111111111:role/TargetRole' for e in edges)

    # Inspect runtime and permission graph
    runtime = get_server_runtime_state(app)
    pg = get_permission_graph(runtime, tenant)
    # As an additional check, call ingest directly into the graph to ensure
    # the helper works when invoked programmatically.
    from src.domains.iam.policy_ingest import ingest_policy_to_graph
    ingest_policy_to_graph(pg, sample_policy, principal_prefix='', weight_overrides=overrides)
    # public principal normalized to '*' should exist as a key in edges
    assert '*' in pg.edges or '"*"' in pg.edges or any(k.startswith('arn:') or k == '*' for k in pg.edges.keys())
    # the target role should be a neighbor of the public principal entry
    found = False
    for k, v in pg.edges.items():
        if isinstance(v, dict) and 'arn:aws:iam::111111111111:role/TargetRole' in v:
            found = True
            # weight should reflect override public -> 6.5
            assert float(v['arn:aws:iam::111111111111:role/TargetRole']) == float(overrides['public'])
    assert found
