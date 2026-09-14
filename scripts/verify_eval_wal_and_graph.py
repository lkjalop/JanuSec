from pathlib import Path
from src.graph.hopgraph import HopGraph
import json

wal = Path('data/benchmarking/eval_wal.log')
print('WAL exists?', wal.exists(), 'size:', wal.stat().st_size if wal.exists() else None)
if wal.exists():
    lines = wal.read_text(encoding='utf-8').splitlines()
    print('WAL lines (last 50):')
    for ln in lines[-50:]:
        print(ln)

hg = HopGraph(wal_path='data/benchmarking/eval_wal.log', snapshot_path='data/benchmarking/eval_snapshot.json')
# Explicitly load snapshot+WAL
try:
    hg.load_snapshot()
    print('Loaded snapshot+WAL: nodes', len(hg.nodes), 'adj entries', sum(len(v) for v in hg.adj.values()))
except Exception as e:
    print('load_snapshot failed:', e)

checks = ['host:host89', 'process:cmd.exe', 'hash:gt0-0']
for c in checks:
    print('\nAdjacency for', c)
    lst = hg.adj.get(c) or []
    print('count', len(lst))
    for e in lst:
        print('  ->', e)

print('\nIncoming to hash:gt0-0')
for src,lst in hg.adj.items():
    for (dst, et, ts, srcv, w) in lst:
        if dst == 'hash:gt0-0':
            print(src, '->', dst, et, ts, srcv, w)

print('\nSource weights:')
print(hg.source_weights)
