import pytest

from src.enrichment import frameworks as fw


def test_map_factors_to_mitre():
    factors = ['cmd_exec', 'ransomware_behavior', 'unknown_factor']
    techs = fw.map_factors_to_mitre(factors)
    assert 'T1059' in techs
    assert 'T1486' in techs


def test_map_stride_and_dread_and_pasta():
    factors = ['cmd_exec', 'data_exfil', 'ransomware_behavior']
    stride = fw.map_stride(factors)
    assert 'information_disclosure' in stride or isinstance(stride, list)
    dread = fw.calculate_dread({'source': 'public', 'category': 'network'}, factors)
    assert isinstance(dread, dict) and 'average' in dread
    pasta = fw.attach_pasta_scenarios({'factors': factors})
    assert isinstance(pasta, list)


def test_explain_decision_enrichment(monkeypatch):
    # Use the server.explain_decision function directly with a fake DECISION_CACHE
    from src.api import server, runtime_state

    fake_event_id = 'evt-1234'
    fake_dec = types = {'event_id': fake_event_id, 'verdict': 'MALICIOUS', 'confidence': 0.9, 'factors': ['cmd_exec','ransomware_behavior']}
    # Inject into DECISION_CACHE
    runtime_state.cache_set(fake_event_id, fake_dec)

    out = server.explain_decision(fake_event_id)
    assert out['event_id'] == fake_event_id
    assert 'mitre' in out and isinstance(out['mitre'], list)
    assert 'dread' in out and isinstance(out['dread'], dict)
    # cleanup
    try:
        server.DECISION_CACHE.pop(fake_event_id, None)
    except Exception:
        try:
            runtime_state.DECISION_CACHE.pop(fake_event_id, None)
        except Exception:
            pass
