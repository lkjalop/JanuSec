import os, time, json
os.environ.setdefault('SCORING_DIVERSITY_WEIGHT','0.1')
os.environ.setdefault('SCORING_DIVERSITY_TARGET','2')
from src.graph.hopgraph import HopGraph
hg = HopGraph()
# build test graph
hg.add_node_attr('host:1', type='host')
hg.add_node_attr('process:1', type='process', name='proc')
hg.add_node_attr('hash:abc', type='hash')
hg.add_node_attr('domain:ex.com', type='domain')
ts = time.time() - 60
hg.add_edge('host:1', 'process:1', 'runs', source='event', ts=ts)
hg.add_edge('process:1', 'hash:abc', 'loads_hash', source='event', ts=ts)
hg.add_edge('process:1', 'domain:ex.com', 'contacts_domain', source='event', ts=ts)
res = hg.explain_chain('host:1', max_depth=3, beam_width=4, top_k=1)
print(json.dumps(res['chains'][0], indent=2))
