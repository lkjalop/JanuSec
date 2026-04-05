import time
from src.pipeline.factor_engine import FactorEngine
from src.pipeline.normalizer import normalize_okta_event, normalize_apigw_event


def test_privilege_chain_escalation_threshold():
    engine = FactorEngine()
    raw = {
        'id': 'okta-1',
        'changeType': 'role_grant',
        'rolesAfter': ['Admin','Billing'],
        'rolesBefore': ['Billing'],
        'privilegeDelta': 25,
        'actor': {'id': 'alice'}
    }
    ev = normalize_okta_event(raw)
    matches = engine.evaluate(ev)
    ids = [m['id'] for m in matches]
    assert 'iam:privilege_chain_escalation' in ids


def test_api_rare_method_combo_detection():
    engine = FactorEngine()
    raw = {
        'id': 'apigw-1',
        'path': '/v1/test/1',
        'methodsSequence': ['OPTIONS','PUT','DELETE','PATCH','GET'],
        'status': 200,
        'tokenId': 'tok-1'
    }
    ev = normalize_apigw_event(raw)
    matches = engine.evaluate(ev)
    ids = [m['id'] for m in matches]
    assert 'api:rare_method_combo' in ids


def test_data_staging_volume_spike_threshold_edge():
    engine = FactorEngine()
    # threshold delta_bytes = 524288000 (500MB) in spec
    ev = {
        'event_id': 'e1',
        'tenant_id': 't1',
        'ts': time.time(),
        'domain': 'data',
        'metrics': {'delta_bytes': 524288000},
        'factors': []
    }
    matches = engine.evaluate(ev)
    ids = [m['id'] for m in matches]
    assert 'data:staging_volume_spike' in ids
