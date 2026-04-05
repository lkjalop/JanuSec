import sys, os, json
here = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
src_path = os.path.join(here, 'src')
if src_path not in sys.path:
    sys.path.insert(0, src_path)

try:
    from graph.hopgraph import GLOBAL_HOPGRAPH
except Exception:
    from src.graph.hopgraph import GLOBAL_HOPGRAPH

for node in ('host:alice','host:host-alice'):
    print(f"\n--- explain_chain for {node} ---")
    ex = GLOBAL_HOPGRAPH.explain_chain(start=node, max_depth=4, beam_width=6, top_k=5)
    print(json.dumps(ex, indent=2))

print('\nTotal edges in graph:', sum(len(v) for v in GLOBAL_HOPGRAPH.adj.values()))
