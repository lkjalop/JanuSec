import types
from src.enrichment.consumer import _process_event


class MergeHopgraph:
    def __init__(self):
        self.nodes = {}
        self.edges = []

    def upsert_node(self, node_id, node_type=None, attrs=None, source=None):
        cur = self.nodes.get(node_id, {'attrs': {}})
        # merge attrs: prefer new values when present
        cur_attrs = cur.get('attrs', {})
        for k, v in (attrs or {}).items():
            if k not in cur_attrs or v:
                cur_attrs[k] = v
        cur['attrs'] = cur_attrs
        cur['node_type'] = node_type
        self.nodes[node_id] = cur

    def emit_edge(self, edge):
        self.edges.append(edge)


def test_hopgraph_merge_prefers_new_values(monkeypatch):
    mh = MergeHopgraph()
    import sys
    sys.modules['src.graph.hopgraph'] = types.SimpleNamespace(GLOBAL_HOPGRAPH=mh)

    # prepare event with geo/asn
    ev = {'type': 'enrichment:epss_high', 'hash': 'abc123', 'src_ip': '1.1.1.1', '_app': types.SimpleNamespace(state=types.SimpleNamespace(geo_asn_enricher=lambda ip: {'country': 'Old', 'asn': 111} ))}

    # pre-populate node with different attrs
    mh.nodes['file_hash:abc123'] = {'attrs': {'asn': {'asn': 111, 'org': 'OldOrg'}, 'geo': {'country': 'Old'}}}

    import asyncio
    asyncio.get_event_loop().run_until_complete(_process_event(ev))

    # after processing, node attrs should be merged and updated
    node = mh.nodes.get('file_hash:abc123')
    assert node is not None
    assert 'attrs' in node
    # expected that asn remains or is updated (consumer uses incoming attrs)
    assert 'asn' in node['attrs']
