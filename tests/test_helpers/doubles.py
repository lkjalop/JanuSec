class DummyHopGraph:
    def __init__(self):
        self.events = []
        # minimal graph structures used by callers/tests
        self.nodes = {}
        self.adj = {}

    def ingest_event(self, ev, source=None):
        self.events.append((ev, source))
        return True

    def add_edge(self, src, dst, etype, source='event', ts=None, attrs=None, weight=None):
        # Ensure nodes exist
        try:
            if src not in self.nodes:
                self.nodes[src] = {'id': src}
            if dst not in self.nodes:
                self.nodes[dst] = {'id': dst}
            lst = self.adj.setdefault(src, [])
            lst.append((dst, etype, ts or 0.0, source or '', float(weight or 1.0)))
        except Exception:
            pass

    def add_node_attr(self, node, **attrs):
        try:
            self.nodes.setdefault(node, {}).update(attrs)
        except Exception:
            pass

    def explain_chain(self, start, max_depth=4, beam_width=5, top_k=3):
        # Return a minimal explain structure so API handlers can proceed
        try:
            sub_nodes = {nid: self.nodes.get(nid, {}) for nid in (self.adj.get(start, []) and [start] or [start])}
            edges = []
            for src, lst in self.adj.items():
                for (dst, et, ts, srcv, w) in lst:
                    edges.append({'src': src, 'dst': dst, 'etype': et, 'ts': ts, 'source': srcv, 'weight': w})
            return {'start': start, 'chains': [], 'subgraph': {'nodes': sub_nodes, 'edges': edges}}
        except Exception:
            return {'start': start, 'chains': [], 'subgraph': {'nodes': {}, 'edges': []}}

    def get_version(self):
        return 0

def dummy_compute_fair_row(row):
    # Simple deterministic output based on canonical keys
    return {'expected_loss': 2000.0, 'dread_inputs': {'damage': 1, 'exploitability': 1}}
