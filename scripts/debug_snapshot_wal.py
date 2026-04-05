import json, time, os
from pathlib import Path
os.environ['PYTHONPATH']='.'
from src.graph.hopgraph import HopGraph
from pathlib import Path
import tempfile
p = Path(tempfile.mkdtemp())
wal = str(p / 'hop_wal.jsonl')
snap = str(p / 'hop_snapshot.json')
initial_nodes = {'host:1': {'id': 'host:1'}, 'proc:a': {'id': 'proc:a'}}
initial_adj = {'host:1': [('proc:a', 'runs', 1000.0, 'event', 1.0)]}
snap_data = {'nodes': initial_nodes, 'adj': initial_adj, 'saved_ts': 1000.0}
with open(snap, 'w', encoding='utf-8') as fh:
    fh.write(json.dumps(snap_data))
extra_op = {'op': 'edge', 'src': 'proc:a', 'dst': 'ip:1.2.3.4', 'etype': 'connects_to', 'srcv': 'event', 'ts': 2000.0, 'attrs': {}, 'w': 1.0}
with open(wal, 'w', encoding='utf-8') as fw:
    fw.write(json.dumps(extra_op) + '\n')
print('paths', snap, wal)
hg = HopGraph(wal_path=wal, snapshot_path=snap)
print('before load: adj keys', list(hg.adj.keys()))
hg.load_snapshot()
print('after load: adj keys', list(hg.adj.keys()))
print('host adj:', hg.adj.get('host:1'))
