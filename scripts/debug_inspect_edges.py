from src.graph.hopgraph import HopGraph
from pathlib import Path
import json
hg = HopGraph(wal_path='data/benchmarking/eval_wal.log', snapshot_path='data/benchmarking/eval_snapshot.json')
checks = ['host:host89', 'process:cmd.exe', 'hash:gt0-0']
for c in checks:
    print('\nAdjacency for', c)
    for e in hg.adj.get(c, []):
        print('  ->', e)
# Also check incoming edges to hash:gt0-0
print('\nIncoming to hash:gt0-0')
for src,lst in hg.adj.items():
    for (dst, et, ts, srcv, w) in lst:
        if dst == 'hash:gt0-0':
            print(src, '->', dst, et, ts, srcv, w)
# Print source_weights
print('\nSource weights:')
print(hg.source_weights)
