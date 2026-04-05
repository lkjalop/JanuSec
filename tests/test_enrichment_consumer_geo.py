import time
import types
import pytest

from src.enrichment.consumer import _process_event


class DummyEnricher:
    def __init__(self, info):
        self.info = info

    def __call__(self, ip):
        # return a copy each call to simulate fresh lookups
        data = dict(self.info)
        data['ip'] = ip
        return data


class DummyHopgraph:
    def __init__(self):
        self.ingested = []
        self.edges = []
        self.upserts = []
        self.merges = []

    def ingest_event(self, ev, source=None):
        # record node attrs mutation intent
        self.ingested.append((ev, source))

    def emit_edge(self, edge):
        self.edges.append(edge)

    def upsert_node(self, node_id, node_type=None, attrs=None, source=None):
        self.upserts.append({'node_id': node_id, 'node_type': node_type, 'attrs': attrs, 'source': source})

    def merge_node_attrs(self, node_id, attrs, source=None):
        self.merges.append({'node_id': node_id, 'attrs': attrs, 'source': source})


def make_app_with_enricher(info):
    app = types.SimpleNamespace()
    state = types.SimpleNamespace()
    state.geo_asn_enricher = DummyEnricher(info)
    app.state = state
    return app


def test_process_event_attaches_geo_and_asn(monkeypatch, tmp_path):
    # Prepare a fake app with enricher returning geo+asn
    info = {
        'country': 'Neverland',
        'country_code': 'NV',
        'city': 'MockCity',
        'latitude': 1.23,
        'longitude': 4.56,
        'asn': 64512,
        'asn_org': 'Test ASN Org',
        'asn_cidr': '10.0.0.0/24',
    }
    app = make_app_with_enricher(info)

    # attach app directly on the event so consumer can find it
    ev = {'type': 'enrichment:epss_high', 'hash': 'deadbeef', 'src_ip': '1.2.3.4', '_app': app}

    # provide a dummy HopGraph to observe ingest_event calls and make it importable
    dummy_hg = DummyHopgraph()
    import sys
    mod = types.SimpleNamespace(GLOBAL_HOPGRAPH=dummy_hg)
    sys.modules['src.graph.hopgraph'] = mod

    # run process
    import asyncio
    asyncio.get_event_loop().run_until_complete(_process_event(ev))

    # event should now have geo and asn keys
    assert 'geo' in ev and isinstance(ev['geo'], dict)
    assert ev['geo']['country'] == 'Neverland'
    assert 'asn' in ev and isinstance(ev['asn'], dict)
    assert ev['asn']['asn'] == 64512
    # HopGraph should have ingested a node event with attrs
    # Consumer prefers upsert/merge; assert one of them was called or ingest_event was used
    assert dummy_hg.upserts or dummy_hg.merges or dummy_hg.ingested, 'HopGraph did not record any node update'
    if dummy_hg.upserts:
        rec = dummy_hg.upserts[-1]
        assert rec['node_type'] == 'file_hash'
        assert rec['attrs']['asn']['asn'] == 64512
    elif dummy_hg.merges:
        rec = dummy_hg.merges[-1]
        assert rec['attrs']['asn']['asn'] == 64512
    else:
        node_ev, src = dummy_hg.ingested[-1]
        assert 'attrs' in node_ev and 'asn' in node_ev['attrs']
        assert node_ev['attrs']['asn']['asn'] == 64512
    # Edge for ASN should have been emitted
    assert any(e.get('type') == 'asn_shared' and e.get('asn') == 64512 for e in dummy_hg.edges)


def test_process_event_no_enricher_noop(monkeypatch):
    # Ensure no enricher on event by setting event _app to None
    ev = {'type': 'enrichment:epss_high', 'hash': 'cafebabe', 'src_ip': '5.6.7.8', '_app': None}
    # Force the runtime app module to have no app to avoid accidental fallback enrichment
    import sys, types
    monkeypatch.setitem(sys.modules, 'src.api.app', types.SimpleNamespace(app=None))
    import asyncio
    asyncio.get_event_loop().run_until_complete(_process_event(ev))
    # Without enricher event must not get geo/asn
    assert 'geo' not in ev
    assert 'asn' not in ev
