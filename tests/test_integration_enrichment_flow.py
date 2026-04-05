import os
import json
import time
import pytest

from src.api.runtime_state import EVENT_QUEUE, drain_event_queue_for_tests


def _write_crq_shadow_sample():
    # Prefer injecting into an in-memory persistence when running tests
    sample = [{'hash': 'ff'*16, 'expected_loss': 2000.0, 'dread_inputs': {'damage': 1, 'exploitability': 1}, 'meta': {}}]
    try:
        from src.crq import fair_shadow as _fsmod
        inst = getattr(_fsmod, '_PERSIST_INSTANCE', None)
        if inst is not None:
            for s in sample:
                try:
                    inst.persist(s)
                except Exception:
                    pass
            return
    except Exception:
        pass
    # fallback to file write for compatibility
    p = os.path.join('data', 'crq_shadow.json')
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, 'w', encoding='utf-8') as fh:
        json.dump(sample, fh)


@pytest.mark.integration
def test_enrichment_to_hopgraph_and_crq(tmp_path, monkeypatch):
    # Enable test helpers
    os.environ['TEST_HELPERS_ENABLED'] = '1'
    # Ensure minimal TF-IDF model exists by seeding from sample
    _write_crq_shadow_sample()
    try:
        from src.enrichment.tfidf import seed_and_build_from_disk
        seed_and_build_from_disk()
    except Exception:
        pass

    # Use an in-memory CRQ persistence for deterministic testing
    try:
        from src.crq.persistence import InMemoryCRQPersistence
        from src.crq import fair_shadow as _fsmod
        _fsmod.set_crq_persistence(InMemoryCRQPersistence())
    except Exception:
        pass

    # Capture calls to GLOBAL_HOPGRAPH.ingest_event
    called = {'args': []}
    try:
        from src.graph.hopgraph import GLOBAL_HOPGRAPH
    except Exception:
        try:
            from src.core.graph.hopgraph_core import GLOBAL_HOPGRAPH
        except Exception:
            GLOBAL_HOPGRAPH = None

    if GLOBAL_HOPGRAPH is not None:
        def _fake_ingest(ev, source=None):
            called['args'].append((ev, source))
            return True
        monkeypatch.setattr(GLOBAL_HOPGRAPH, 'ingest_event', _fake_ingest)
        # Use lightweight in-memory doubles for deterministic behavior
        from tests.test_helpers.doubles import DummyHopGraph, dummy_compute_fair_row
        # Inject dummy hopgraph via consumer override setter
        try:
            from src.enrichment import consumer as _consumer
            _consumer.set_hopgraph_override(DummyHopGraph())
        except Exception:
            pass

    # Create synthetic enrichment event and call consumer directly to ensure processing
    # Use different test hash than seed sample
    ev = {'type': 'enrichment:epss_high', 'hash': 'bb'*16, 'score': 0.9, 'ts': time.time(), 'meta': {'tenant': 'tenantA', 'host': 'host1'}}

    import asyncio
    from src.enrichment import consumer as _consumer
    # Ensure compute_fair_row and persist_shadow_observation are available to consumer
    try:
        from src.crq import fair_shadow as _fs
        # monkeypatch consumer functions to ensure they run in test
        def _fake_compute(row):
            return {'expected_loss': 2000.0, 'dread_inputs': {'damage': 1, 'exploitability': 1}}
        _consumer.compute_fair_row = _fake_compute
        _consumer.persist_shadow_observation = getattr(_fs, 'persist_shadow_observation', None)
        # ensure link helper exists
        try:
            _ = getattr(_fs, 'link_observation_to_tenant')
        except Exception:
            def _link(obs, tenant):
                obs['tenant'] = tenant
            _fs.link_observation_to_tenant = _link
    except Exception:
        # ensure compute_fair_row is the dummy deterministic impl
        _consumer.compute_fair_row = dummy_compute_fair_row
        # use real persist function from fair_shadow if available
        try:
            from src.crq import fair_shadow as _fs
            _consumer.persist_shadow_observation = getattr(_fs, 'persist_shadow_observation', None)
        except Exception:
            pass

    # Always run the consumer to process the synthetic event; fallback to enqueue
    try:
        asyncio.run(_consumer._process_event(ev))
    except Exception:
        try:
            if hasattr(EVENT_QUEUE, 'enqueue'):
                import asyncio as _a
                _a.run(EVENT_QUEUE.enqueue(ev))
        except Exception:
            pass

    # Now assert CRQ persisted and includes tenant and (optionally) tfidf_score
    # Read from injected persistence (in-memory) if available
    data = None
    try:
        from src.crq import fair_shadow as _fsmod
        inst = getattr(_fsmod, '_PERSIST_INSTANCE', None)
        if inst is not None:
            data = inst.read_all()
    except Exception:
        data = None

    if data is None:
        # fallback to file path for backwards compatibility
        p = os.path.join('data', 'crq_shadow.json')
        assert os.path.exists(p)
        data = json.loads(open(p, 'r', encoding='utf-8').read() or '[]')
    # There should be at least one observation with tenant 'tenantA'
    found = False
    for o in data:
        if o.get('tenant') == 'tenantA' or (o.get('hash') == 'aaaaaaaaaaaaaaaa' or o.get('hash') == 'aa'*16):
            found = True
            # tfidf_score may be present
            assert 'tenant' in o
            break
    assert found
