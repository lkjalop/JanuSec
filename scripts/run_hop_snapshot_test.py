import os, json, tempfile, shutil
from pathlib import Path

# Set lightweight/test env vars before imports
os.environ.setdefault('PLATFORM_LITE_INIT','1')
os.environ.setdefault('TEST_HELPERS_ENABLED','1')
os.environ.setdefault('DISABLE_DB','1')

# Create temp dir under project to keep paths stable
tmp = Path('tmp/hop_test_runner')
if tmp.exists():
    shutil.rmtree(tmp)
tmp.mkdir(parents=True)

wal = str(tmp / 'hop_wal.jsonl')
snap = str(tmp / 'hop_snapshot.json')

initial_nodes = {
    'host:1': {'id': 'host:1'},
    'proc:a': {'id': 'proc:a'},
}
initial_adj = {
    'host:1': [('proc:a', 'runs', 1000.0, 'event', 1.0)]
}

snap_data = {'nodes': initial_nodes, 'adj': initial_adj, 'saved_ts': 1000.0}
with open(snap, 'w', encoding='utf-8') as fh:
    fh.write(json.dumps(snap_data))

extra_op = {'op': 'edge', 'src': 'proc:a', 'dst': 'ip:1.2.3.4', 'etype': 'connects_to', 'srcv': 'event', 'ts': 2000.0, 'attrs': {}, 'w': 1.0}
with open(wal, 'w', encoding='utf-8') as fw:
    fw.write(json.dumps(extra_op) + '\n')

# Import HopGraph and run
import sys
# ensure repo root on sys.path for local imports
repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))
from src.graph.hopgraph import HopGraph
hg = HopGraph(wal_path=wal, snapshot_path=snap)
print('Before load_snapshot: adj_keys=', list(hg.adj.keys()))
hg.load_snapshot()
print('After load_snapshot: adj_keys=', list(hg.adj.keys()))
print('host:1 entries=', hg.adj.get('host:1'))
print('proc:a entries=', hg.adj.get('proc:a'))

# Print debug log if exists
logp = Path('tmp/hopgraph_load_snapshot.log')
if logp.exists():
    print('\n--- hopgraph_load_snapshot.log ---')
    print(logp.read_text(encoding='utf-8'))
else:
    print('\nNO hopgraph_load_snapshot.log found')
