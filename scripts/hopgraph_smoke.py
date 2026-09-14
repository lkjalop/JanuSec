# HopGraph smoke test
# Adds a few edges to GLOBAL_HOPGRAPH, runs explain_chain and k_hops, prints results.
import json, traceback, sys, os
from time import sleep

# Make imports resilient whether PYTHONPATH is set to repo root or src/
try:
    from src.graph.hopgraph import GLOBAL_HOPGRAPH
except Exception:
    try:
        # If src/ is the import root, import as graph.hopgraph
        from graph.hopgraph import GLOBAL_HOPGRAPH
    except Exception:
        # Try to add repo src path dynamically
        here = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        src_path = os.path.join(here, 'src')
        if src_path not in sys.path:
            sys.path.insert(0, src_path)
        try:
            from graph.hopgraph import GLOBAL_HOPGRAPH
        except Exception as e:
            print('IMPORT_ERROR', e)
            raise

def summary():
    nodes = len(GLOBAL_HOPGRAPH.nodes)
    edges = sum(len(v) for v in GLOBAL_HOPGRAPH.adj.values())
    print(f'Version: {GLOBAL_HOPGRAPH.get_version()}, nodes: {nodes}, edges: {edges}')

try:
    print('--- HopGraph smoke test start ---')
    summary()
    # add some synthetic edges
    GLOBAL_HOPGRAPH.add_edge('host:alice', 'process:alice:1001', 'runs', source='event')
    GLOBAL_HOPGRAPH.add_edge('process:alice:1001', 'ip:10.0.0.5', 'connects_to', source='event')
    GLOBAL_HOPGRAPH.add_edge('process:alice:1001', 'domain:evil.com', 'contacts_domain', source='event')
    GLOBAL_HOPGRAPH.add_edge('ip:10.0.0.5', 'domain:evil.com', 'dns_a', source='event')
    # small pause to allow timestamps to differ
    sleep(0.02)
    # ingest a canonical event
    evt = {'timestamp': 1620000000, 'host': 'bobworkstation', 'process': 'svchost.exe', 'pid': 4242, 'dst_ip': '8.8.8.8', 'domain': 'example.com', 'file_hash': 'deadbeefcafebabe'}
    try:
        from src.core.graph.hopgraph_utils import safe_upsert_node
    except Exception:
        safe_upsert_node = None
    try:
        if safe_upsert_node is not None and evt.get('type') == 'file_hash' and evt.get('id'):
            safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', evt.get('id'), attrs=evt.get('attrs') or {}, source='sensor')
        else:
            GLOBAL_HOPGRAPH.ingest_event(evt, source='sensor')
    except Exception:
        try:
            GLOBAL_HOPGRAPH.ingest_event(evt, source='sensor')
        except Exception:
            pass
    print('\nAfter adding edges:')
    summary()
    # Run k_hops
    kh = GLOBAL_HOPGRAPH.k_hops('host:alice', k=3)
    print('\nK-hops result for host:alice:')
    print(json.dumps(kh, indent=2))
    # Run explain_chain
    ex = GLOBAL_HOPGRAPH.explain_chain(start='host:alice', max_depth=4, beam_width=8, top_k=5)
    print('\nExplain_chain result for host:alice:')
    print(json.dumps(ex, indent=2))
    print('--- HopGraph smoke test end ---')
except Exception:
    print('EXCEPTION during hopgraph smoke:')
    traceback.print_exc()
    raise
