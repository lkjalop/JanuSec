import time
import pytest

from src.api.server import _process_endpoint_event, LogEvent, LogBatchContext, _RUNTIME


class DummyRulesEngine:
    def __init__(self):
        self.last_event = None

    def evaluate_event(self, event):
        # capture the event passed to rules engine for inspection
        self.last_event = dict(event)
        return []

    def score_and_classify(self, hits):
        return {'verdict': 'OBSERVE', 'score': 0.0}


@pytest.mark.asyncio
async def test_graph_enrichment_called_before_evaluate(monkeypatch):
    # Prepare a dummy runtime and context
    dummy_re = DummyRulesEngine()
    # attach to runtime module (_rt used by server imports)
    import src.api.runtime_state as _rt_mod
    monkeypatch.setattr(_rt_mod, 'rules_engine', dummy_re, raising=False)

    # Build a minimal LogEvent; include a user so the enricher cache key is set
    evt = LogEvent(id='evt-test-graph', host='host-test', details={}, model_config={})
    # Build context: include_rules True so enrichment is executed
    ctx = LogBatchContext(runtime=_RUNTIME, include_rules=True, classify=False, send_alerts=False, tenant_id='default', nx_enabled=False, dedup_ttl=10.0)

    processed, alert = await _process_endpoint_event(evt, ctx)

    # The dummy rules engine should have captured the event passed to evaluate_event
    assert dummy_re.last_event is not None, 'evaluate_event was not invoked by pipeline'

    # Check for graph-enrichment keys on the event passed to evaluate_event
    # Cached/default values are integers/None; ensure keys exist
    for k in ('graph_lateral_chain_len', 'graph_lateral_chain_hosts', 'graph_phase_counts', 'graph_first_dc_ts', 'graph_initial_access_ts'):
        assert k in dummy_re.last_event, f'Enrichment key {k} missing from event passed to evaluate_event'
