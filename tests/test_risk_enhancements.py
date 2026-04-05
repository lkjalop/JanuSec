import os, sys, time, pathlib, json
from fastapi.testclient import TestClient

# Make src importable
root = pathlib.Path(__file__).resolve().parents[1]
src = root / 'src'
sp = str(src)
if sp not in sys.path:
    sys.path.insert(0, sp)

# Stub optional routers
import types
from fastapi import APIRouter
if 'api.soar_endpoints' not in sys.modules:
    sys.modules['api.soar_endpoints'] = types.SimpleNamespace(router=APIRouter())

from src.api.server import app, DECISION_CACHE, _record_decision
from src.api import runtime_state as _rs
from core.risk_score import compose_risk_score


def _wait():
    time.sleep(0.05)


def test_yaml_hot_reload(tmp_path, monkeypatch):
    yaml_path = tmp_path / 'risk_weights.yaml'
    yaml_path.write_text('net:beacon_periodic: 0.3\ndns:tunnel_suspected: 0.2\n', encoding='utf-8')
    monkeypatch.setenv('RISK_WEIGHTS_YAML', str(yaml_path))
    import importlib, core.risk_score as rs
    importlib.reload(rs)
    dec = {'factors':['net:beacon_periodic','dns:tunnel_suspected'], 'confidence':1.0}
    out1 = rs.compose_risk_score(dec)
    # Update YAML
    time.sleep(0.05)  # ensure mtime advances on some filesystems
    yaml_path.write_text('net:beacon_periodic: 0.1\ndns:tunnel_suspected: 0.05\n', encoding='utf-8')
    os.utime(yaml_path, None)
    # Force second call (hot reload should detect mtime)
    out2 = rs.compose_risk_score(dec)
    # If still unchanged (rare mtime resolution issue), call a third time
    if out2['raw_score'] == out1['raw_score']:
        time.sleep(0.05)
        os.utime(yaml_path, None)
    out2 = rs.compose_risk_score(dec)
    # Expect weights changed (raw_score decreases)
    assert out2['raw_score'] < out1['raw_score']


def test_cluster_novelty_contribution(monkeypatch):
    from src.api import runtime_state as _rs
    _rs.DECISION_CACHE.clear()
    dec = {'event_id':'evt-novelty','id':'evt-novelty','factors':['net:test'], 'confidence':1.0, 'novelty_score':0.5}
    out = compose_risk_score(dec)
    # Should include cluster:novelty factor capped (default max 0.4)
    assert any(b['factor']=='cluster:novelty' for b in out['breakdown'])
    novelty_entry = [b for b in out['breakdown'] if b['factor']=='cluster:novelty'][0]
    assert novelty_entry['contribution'] <= 0.4


def test_completeness_penalty(monkeypatch):
    monkeypatch.setenv('RISK_COMPLETENESS_EXPECTED_CLASSES','net,dns,endpoint')
    monkeypatch.setenv('RISK_COMPLETENESS_MIN_PRESENT','2')
    monkeypatch.setenv('RISK_COMPLETENESS_PENALTY','0.2')
    dec = {'factors':['net:a_only'], 'confidence':1.0}
    out = compose_risk_score(dec)
    # Penalty appears because only one class present
    assert any(b['factor']=='penalty:incomplete' for b in out['breakdown'])
    # Add second class to satisfy minimal coverage
    dec2 = {'factors':['net:a_only','dns:b_only'], 'confidence':1.0}
    out2 = compose_risk_score(dec2)
    assert not any(b['factor']=='penalty:incomplete' for b in out2['breakdown'])


def test_sigmoid_calibration(monkeypatch):
    # Disable sigmoid first
    if 'RISK_SIGMOID_CALIBRATION' in os.environ: del os.environ['RISK_SIGMOID_CALIBRATION']
    dec = {'factors':['net:x','dns:y'], 'confidence':1.0}
    base = compose_risk_score(dec)
    # Enable sigmoid with steep slope centered at 0.5 to accentuate difference
    monkeypatch.setenv('RISK_SIGMOID_CALIBRATION','1')
    monkeypatch.setenv('RISK_SIGMOID_K','6.0')
    monkeypatch.setenv('RISK_SIGMOID_X0','0.5')
    cal = compose_risk_score(dec)
    # Raw score identical, final score transformed (unless raw at boundary)
    assert abs(cal['raw_score'] - base['raw_score']) < 1e-9
    # With k>0, sigmoid(raw) != raw for mid-range values
    if 0.05 < base['raw_score'] < 0.95:
        assert abs(cal['score'] - base['score']) > 1e-6


def test_extended_explain_endpoint(monkeypatch):
    _rs.DECISION_CACHE.clear()
    monkeypatch.setenv('RISK_HIGH_THRESHOLD','0.3')
    client = TestClient(app)
    # Create a decision quickly via record helper to ensure risk fields present
    dec_id = 'evt-explain-1'
    from core.risk_score import compose_risk_score as _crs
    _rs.cache_set(dec_id, {'event_id': dec_id, 'id': dec_id, 'factors':['net:a','dns:b'], 'confidence':1.0})
    cached = _rs.cache_get(dec_id)
    rs = _crs(cached)
    # Attach risk fields to cached object/dict in a safe way
    try:
        if hasattr(cached, '__dict__') or hasattr(cached, 'model_dump'):
            setattr(cached, 'risk_score', rs['score'])
            setattr(cached, 'risk_breakdown', rs['breakdown'])
            setattr(cached, 'risk_method', rs['method'])
            setattr(cached, 'risk_ci95', rs['ci95'])
            setattr(cached, 'risk_variance', rs['variance'])
            setattr(cached, 'risk_raw_score', rs['raw_score'])
        else:
            cached['risk_score'] = rs['score']
            cached['risk_breakdown'] = rs['breakdown']
            cached['risk_method'] = rs['method']
            cached['risk_ci95'] = rs['ci95']
            cached['risk_variance'] = rs['variance']
            cached['risk_raw_score'] = rs['raw_score']
    except Exception:
        _rs.cache_set(dec_id, dict(cached) if hasattr(cached, 'items') else cached)
    r = client.get(f'/api/v1/risk/{dec_id}/explain')
    assert r.status_code == 200
    body = r.json()
    for key in ['score','raw_score','breakdown','variance','ci95','method']:
        assert key in body
    assert isinstance(body['breakdown'], list)
    assert len(body['breakdown']) >= 2
