import json
from pathlib import Path
p = Path('data/benchmarking/debugs/deep_explain_incident1.json')
data = json.loads(p.read_text(encoding='utf-8'))
chains = data.get('chains', [])
found = []
for idx,ch in enumerate(chains):
    for n in ch.get('nodes', []):
        if isinstance(n, str) and n.startswith('hash:gt'):
            found.append({'chain_index': idx, 'score': ch.get('score'), 'nodes': ch.get('nodes')})
            break
print('Found gt hash in chains count:', len(found))
for f in found[:10]:
    print(f)
# Also print top-50 chain dst nodes summary
print('\nTop 50 chains dst hash prefixes:')
for i,ch in enumerate(chains[:50]):
    dst = ch['nodes'][-1]
    print(i, dst)
