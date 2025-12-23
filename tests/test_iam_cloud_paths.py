import json
import os
import pytest

from src.core.correlation.rules import registry as reg


@pytest.mark.parametrize('rule_id,vector_path', [
    ('cloud_service_account_policy_drift', 'tests/data/cloud_service_account_policy_drift_event.json'),
    ('cloud_role_escalation_from_vm', 'tests/data/cloud_role_escalation_from_vm_event.json'),
    ('discovery_ad_credential_dump', 'tests/data/discovery_ad_credential_dump_event.json'),
    ('cloud_service_account_key_creation', 'tests/data/cloud_service_account_key_creation_event.json'),
    ('cloud_policy_attach_broad_roles', 'tests/data/cloud_policy_attachment_broad_roles_event.json'),
    ('cloud_access_key_rotation_anomaly', 'tests/data/cloud_access_key_rotation_anomaly_event.json'),
    ('cloud_org_policy_attach_wildcard', 'tests/data/cloud_org_policy_attach_wildcard_event.json'),
    ('cloud_access_key_creation_no_rotation_cross_account', 'tests/data/cloud_access_key_creation_no_rotation_cross_account_event.json'),
])
def test_iam_cloud_pack(rule_id, vector_path):
    full_path = os.path.join(os.getcwd(), vector_path)
    assert os.path.exists(full_path), f"Missing vector {vector_path}"
    with open(full_path, 'r', encoding='utf-8') as fh:
        payload = json.load(fh)
    hits = reg.CORRELATION_RULES.evaluate(payload)
    hit_names = set()
    for h in hits:
        if hasattr(h, 'rule'):
            hit_names.add(getattr(h, 'rule'))
        elif hasattr(h, 'name'):
            hit_names.add(getattr(h, 'name'))
    assert rule_id in hit_names, f"Rule {rule_id} did not fire; hits={hit_names}"
import asyncio
import collections
import pytest

# Minimal runtime with sanitized events deque
class _Runtime:
    def __init__(self, events):
        self.sanitized_events = collections.deque(events, maxlen=100)

@pytest.mark.asyncio
async def test_iam_privilege_edges():
    from src.api.graph_sessions import build_session
    # Event triggers iam_privilege_escalation detector
    rt = _Runtime([
        {
            'domain': 'cloud',
            'eventSource': 'iam.amazonaws.com',
            'eventName': 'AttachUserPolicy',
            'userName': 'alice',
            'policy': 'AdministratorAccess'
        }
    ])
    payload = {'session_ids': ['batch-overlap-a','batch-overlap-b'], 'correlate': True, 'ewma': False}
    res = await build_session(payload, runtime_override=rt)
    g = res['summary']['graph_summary']
    nodes = {n['id'] for n in g['nodes']}
    edges = {(e['src'], e['dst'], e['type']) for e in g['edges']}
    assert 'user:alice' in nodes
    assert 'policy:AdministratorAccess' in nodes
    assert ('user:alice','policy:AdministratorAccess','attach_policy') in edges

@pytest.mark.asyncio
async def test_cloudtrail_high_risk_edges():
    from src.api.graph_sessions import build_session
    # Event triggers cloudtrail_high_risk detector
    rt = _Runtime([
        {
            'domain': 'cloud',
            'eventSource': 'iam.amazonaws.com',
            'eventName': 'CreateAccessKey',
            'userName': 'bob',
            'sourceIPAddress': '1.2.3.4'
        }
    ])
    payload = {'session_ids': ['batch-overlap-c','batch-overlap-d'], 'correlate': True, 'ewma': False}
    res = await build_session(payload, runtime_override=rt)
    g = res['summary']['graph_summary']
    nodes = {n['id'] for n in g['nodes']}
    edges = {(e['src'], e['dst'], e['type']) for e in g['edges']}
    assert 'event:CreateAccessKey' in nodes
    assert 'user:bob' in nodes
    assert 'ip:1.2.3.4' in nodes
    assert ('user:bob','event:CreateAccessKey','invokes') in edges
    assert ('ip:1.2.3.4','event:CreateAccessKey','source_ip') in edges


def test_iam_cross_cloud_edgecase_gcp():
    full_path = os.path.join(os.getcwd(), 'tests/data/cloud_access_key_creation_cross_tenant_gcp_event.json')
    assert os.path.exists(full_path), "Missing GCP cross-tenant vector"
    with open(full_path, 'r', encoding='utf-8') as fh:
        payload = json.load(fh)
    hits = reg.CORRELATION_RULES.evaluate(payload)
    names = {getattr(h, 'rule', getattr(h, 'name', None)) for h in hits}
    assert 'cloud_access_key_creation_no_rotation_cross_account' in names
