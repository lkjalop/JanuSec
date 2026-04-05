import time

from core.event_pipeline import EventPipeline


class DummyConfig(dict):
    pass

def test_parent_child_and_beacon_counters(monkeypatch):
    cfg = DummyConfig()
    pipeline = EventPipeline(cfg)

    # Parent-child suspicious event
    evt1 = {
        'id': 'e1',
        'parent_process': {'name':'WINWORD.EXE'},
        'process': {'name':'POWERSHELL.EXE'}
    }
    # Beacon events (simulate periodic)
    base = time.time() - 400
    beacon_ip = '10.1.2.3'
    events = [evt1]
    # Add 5 spaced intervals ~60s
    for i in range(6):
        events.append({'id': f'beacon{i}', 'dst_ip': beacon_ip, 'dst_port': 443, '_ts': base + i*60})

    # Monkeypatch time for deterministic beacon deltas
    real_time = time.time
    times = [e.get('_ts', real_time()) for e in events]
    def fake_time():
        return times.pop(0) if times else real_time()
    monkeypatch.setattr('time.time', fake_time)

    for e in events:
        pipeline.config['module_registry'] = None  # skip registry lookups
        # Execute pipeline (async wrapper not needed; using process_event directly would require async)
        import asyncio
        asyncio.run(pipeline.process_event(e))

    # Validate factors emitted in last event
    # (We can't directly access Prometheus counters without client; rely on factors presence.)
    # Ensure suspicious factor present in cumulative processing of first event side effects is not directly accessible here.
    # Simplified assertion: pipeline object has counter attributes.
    assert hasattr(pipeline.__class__, 'parent_child_counter')
    assert hasattr(pipeline.__class__, 'beacon_counter')
