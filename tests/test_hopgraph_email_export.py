from src.core.hunt.evidence_envelope import EvidenceEnvelope
from src.api.graph_sessions import build_session
import asyncio


def make_envelope_with_emission():
    env = EvidenceEnvelope(event={'id':'e1'})
    env.add_emission('email_bec', ['email:display_name_spoof','email:url_login_keyword'], notes='test', latency_ms=1.0)
    return env


def test_envelope_export_signals():
    env = make_envelope_with_emission()
    sigs = env.export_hopgraph_signals()
    assert any(s.get('factor') == 'email:display_name_spoof' for s in sigs)


def test_graph_sessions_accepts_test_emissions(monkeypatch):
    # Build payload with test_emissions to ensure graph_sessions merges them
    env = make_envelope_with_emission()
    sigs = env.export_hopgraph_signals()
    # enqueue into the in-memory hopgraph queue (production wiring)
    from src.core.hunt.hopgraph_queue import enqueue
    enqueue('__USE_CURRENT__', sigs)
    payload = {'session_ids': ['batch-overlap-1','batch-overlap-2'], 'correlate': True}

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    res = loop.run_until_complete(build_session(payload, request=None))
    assert 'summary' in res
    s = res['summary']
    # ensure our emitted factors were included in summary.factors
    factors = s.get('factors') or []
    assert any('email:display_name_spoof' in str(f) for f in factors)
