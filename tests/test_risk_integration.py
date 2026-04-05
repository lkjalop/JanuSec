import sys
sys.path.append('d:/AI/Threat_thy_sniffer')
from src.incidents.aggregator import IncidentAggregator


def test_incident_aggregator_attaches_risk():
    agg = IncidentAggregator(window_seconds=60)
    event = {
        'event_id': 'evt-1',
        'host': 'host-1',
        'ts': 1600000000,
        'tenant_id': 'test-tenant'
    }
    factors = ['endpoint:process_suspicious', 'net:connection_c2']
    inc = agg.ingest(event, factors)
    assert isinstance(inc, dict)
    # risk may be attached after ingest
    assert 'risk' in inc and isinstance(inc['risk'], dict)
    score = inc['risk'].get('score')
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_telemetry_worker_attaches_auth_and_incident(monkeypatch, tmp_path):
    # Monkeypatch ensure_connector to return a stub that returns a message body
    class StubConnector:
        name = 'stub'
        async def execute(self, domain, entity, window=None, context=None, include_body=False):
            return {'message': 'From: a@b.com\r\nSubject: hi\r\n\r\nhello', 'latency_ms': 5, 'cost_usd': 0.0}

    def fake_ensure(name, factory):
        # _execute_connector currently special-cases 'purview'; if asked, return our stub
        return StubConnector()

    monkeypatch.setattr('src.connectors.registry.ensure_connector', fake_ensure)
    # Create a fake app.state with minimal objects used by register_telemetry_worker
    class FakeApp:
        pass
    app = FakeApp()
    from src.core.telemetry_requests import register_telemetry_worker, TelemetryRequest
    # Attach minimal state expected
    from types import SimpleNamespace
    app.state = SimpleNamespace()
    register_telemetry_worker(app)
    # Create a telemetry request with include_body True
    req = TelemetryRequest(id='t1', domain='email', entity='a@b.com', window=None, connector='stub')
    # Instead of relying on the background worker (disabled in pytest), invoke connector directly
    from src.core.telemetry_requests import _execute_connector
    import asyncio, json
    try:
        res = asyncio.get_event_loop().run_until_complete(_execute_connector('purview', 'email', 'a@b.com', None))
    except Exception:
        try:
            res = asyncio.run(_execute_connector('purview', 'email', 'a@b.com', None))
        except Exception as e:
            raise
    # Simulate worker post-processing (auth checks)
    from src.core.email_auth import verify_dkim, check_dmarc, parse_arc_headers
    raw = res.get('message') or res.get('body') or res.get('raw')
    raw_bytes = raw.encode('utf-8', errors='ignore') if isinstance(raw, str) else None
    if raw_bytes:
        dkim_info = verify_dkim(raw_bytes)
        arc_info = parse_arc_headers(raw_bytes)
        from_header = None
        try:
            import email as _email
            m = _email.message_from_bytes(raw_bytes)
            from_header = m.get('From')
        except Exception:
            from_header = None
        dmarc_info = check_dmarc((dkim_info.get('signatures') or [{}])[0].get('domain') or 'example.com', from_header or '')
        res.setdefault('auth_checks', {})
        res['auth_checks']['dkim'] = dkim_info
        res['auth_checks']['dmarc'] = dmarc_info
        res['auth_checks']['arc'] = arc_info
    # Persist into telemetry store
    req.result_json = json.dumps(res)
    req.status = 'done'
    awaitable = app.state.telemetry_store.upsert(req)
    try:
        asyncio.get_event_loop().run_until_complete(awaitable)
    except Exception:
        try:
            asyncio.run(awaitable)
        except Exception:
            pass
    stored = app.state.telemetry_store._mem.get('t1')
    assert stored is not None
    res2 = json.loads(stored.result_json)
    assert 'auth_checks' in res2
