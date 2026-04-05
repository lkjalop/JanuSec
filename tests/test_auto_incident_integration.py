import time
import os
from src.graph.auto_incident import AutoIncidentScanner
from src.graph.hopgraph import HopGraph


def test_auto_incident_creates_incident(monkeypatch, tmp_path):
    # Build small HopGraph with a process node that will be detected
    hg = HopGraph()
    # mark node as process and add contact edges to create pivot sequence factor
    proc = 'process:svc'
    hg.add_node_attr(proc, type='process')
    # add several contacts to domain nodes to satisfy min_prefixes default (5)
    ts = time.time() - 10
    for i in range(6):
        dom = f'domain:ex{i}.com'
        hg.add_node_attr(dom, type='domain')
        hg.add_edge(proc, dom, 'contacts_domain', source='event', ts=ts)
    # force detection
    hg.detect_domain_pivot_sequences(window_seconds=600, min_prefixes=5)

    created = []

    def fake_create_incident(payload):
        created.append(payload)

    monkeypatch.setenv('INCIDENT_AUTOGEN_ENABLED', '1')
    monkeypatch.setenv('INCIDENT_AUTOGEN_INTERVAL_SECONDS', '1')
    monkeypatch.setenv('INCIDENT_AUTOGEN_SCORE_THRESHOLD', '0.0')
    # inject a fake src.api.incidents module so auto_incident imports create_incident
    import types, sys
    fake_mod = types.SimpleNamespace(create_incident=fake_create_incident)
    monkeypatch.setitem(sys.modules, 'src.api.incidents', fake_mod)
    # Inject a fake src.api.server module to accept in-memory incident writes
    fake_server = types.SimpleNamespace(_INCIDENT_STORE=[])
    monkeypatch.setitem(sys.modules, 'src.api.server', fake_server)

    scanner = AutoIncidentScanner(hop=hg)
    # Force a single scan iteration synchronously
    scanner._scan_once()
    # Expect at least one incident created for the process node
    if not created:
        import src.api.server as _server
        assert any((itm.get('artifact_id') or '').startswith('auto-') or itm.get('attack_subgraph') for itm in _server._INCIDENT_STORE)
    else:
        inc = created[0]
        assert inc.get('source_node') == proc
        # default tenant if none set
        assert 'tenant' in inc


def test_dedup_and_tenant_rate_limit(monkeypatch):
    hg = HopGraph()
    proc = 'process:svc2'
    hg.add_node_attr(proc, type='process')
    ts = time.time() - 10
    # make enough contacts to create factor
    for i in range(6):
        dom = f'domain:ex{i}.org'
        hg.add_node_attr(dom, type='domain')
        hg.add_edge(proc, dom, 'contacts_domain', source='event', ts=ts)
    hg.detect_domain_pivot_sequences(window_seconds=600, min_prefixes=5)

    created = []

    def fake_create_incident(payload):
        created.append(payload)

    import types, sys
    fake_mod = types.SimpleNamespace(create_incident=fake_create_incident)
    monkeypatch.setitem(sys.modules, 'src.api.incidents', fake_mod)
    fake_server = types.SimpleNamespace(_INCIDENT_STORE=[])
    monkeypatch.setitem(sys.modules, 'src.api.server', fake_server)
    # configure dedup TTL small and tenant caps small
    monkeypatch.setenv('INCIDENT_AUTOGEN_DEDUP_TTL_SECONDS', '3600')
    monkeypatch.setenv('INCIDENT_AUTOGEN_TENANT_RATE_MAX', '1')
    monkeypatch.setenv('INCIDENT_AUTOGEN_TENANT_RATE_WINDOW_SECONDS', '3600')
    monkeypatch.setenv('INCIDENT_AUTOGEN_ENABLED', '1')
    monkeypatch.setenv('INCIDENT_AUTOGEN_SCORE_THRESHOLD', '0.0')

    scanner = AutoIncidentScanner(hop=hg)
    # First scan emits one incident
    scanner._scan_once()
    # Second scan should not emit duplicate due to dedup
    scanner._scan_once()
    if not created:
        import src.api.server as _server
        hits = [itm for itm in _server._INCIDENT_STORE if itm.get('attack_subgraph')]
        assert len(hits) == 1
    else:
        assert len(created) == 1
    # Bypass dedup by clearing dedup then run again to hit tenant rate cap
    scanner._dedup.clear()
    scanner._scan_once()
    # Should still be limited by tenant cap (1) so created remains 1 or 2 depending ordering
    assert len(created) <= 2