import time
from src.core.graph.graph_features import enrich_event_with_graph
from src.core.correlation.rules.registry import CORRELATION_RULES, record_fp, record_tp


class _FakeGraph:
    def __init__(self):
        pass

    def detect_lateral_chain(self, user, within_seconds):
        # return two chains example
        return [
            {'nodes': [{'host': 'hostA'}, {'host': 'hostB'}, {'host': 'hostC'}]},
            {'nodes': [{'host': 'hostD'}, {'host': 'hostE'}]}
        ]

    def reconstruct_attack(self, seed, depth=3):
        return {
            'timeline': [
                {'phase': 'initial_access', 'ts': time.time() - 3600, 'host': 'hostA'},
                {'phase': 'execution', 'ts': time.time() - 3500, 'host': 'hostA'},
                {'phase': 'lateral', 'ts': time.time() - 3000, 'host': 'hostB'},
            ]
        }


def test_graph_enrich_and_rules(monkeypatch):
    # monkeypatch get_graph used by graph_features
    import src.core.graph.hopgraph_lite as hg
    monkeypatch.setattr(hg, 'get_graph', lambda: _FakeGraph())

    # Build a synthetic event with minimal fields
    ev = {'user': 'alice', 'id': 'evt-1', 'command_line': 'powershell -enc ABCDEF...'}
    enriched = enrich_event_with_graph(ev.copy(), seed_event_id='evt-1', user='alice')

    # Confirm graph fields present
    assert enriched.get('graph_lateral_chain_len', 0) >= 3
    assert enriched.get('graph_lateral_chain_hosts', 0) >= 3

    # Evaluate rules and expect lm_graph_chain_len3 to fire
    fired = CORRELATION_RULES.evaluate(enriched)
    names = [r.name for r in fired]
    assert 'lm_graph_chain_len3' in names

    # test FP/TP counters update path (use registry calls directly)
    record_tp('lm_graph_chain_len3')
    record_fp('exec_powershell_encoded')
    metrics = CORRELATION_RULES.get_rule_metrics()
    assert metrics.get('lm_graph_chain_len3', {}).get('tp', 0) >= 1
    assert metrics.get('exec_powershell_encoded', {}).get('fp', 0) >= 1
