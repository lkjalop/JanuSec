from pathlib import Path
from src.graph.hopgraph import HopGraph
import json
p = Path('data/benchmarking/benchmarks/benchmark_campaign_v3_10000_aligned')
hg = HopGraph(wal_path='data/benchmarking/eval_wal.log', snapshot_path='data/benchmarking/eval_snapshot.json')
# collect gt hashes
gt = json.loads(p.joinpath('ground_truth.json').read_text(encoding='utf-8'))
gt_hashes = set()
gt_hosts = set()
for inc in gt:
    for step in inc.get('chain', []) or []:
        if step.get('file_hash'):
            gt_hashes.add(str(step.get('file_hash')))
    if inc.get('chain') and inc['chain'][0].get('host'):
        gt_hosts.add(inc['chain'][0].get('host'))

for ln in p.joinpath('events.jsonl').read_text(encoding='utf-8').splitlines():
    if not ln.strip():
        continue
    ev = json.loads(ln)
    if 'timestamp' not in ev and 'ts' in ev:
        ev['timestamp'] = ev.get('ts')
    if 'file_hash' not in ev and 'sha256' in ev:
        ev['file_hash'] = ev.get('sha256')
    if 'domain' not in ev and 'qname' in ev:
        ev['domain'] = ev.get('qname')
    ingest_source = 'eval'
    try:
        fh = ev.get('file_hash') or ''
        hst = ev.get('host') or ''
        if isinstance(fh, str) and fh in gt_hashes:
            ingest_source = 'intel_feed'
        elif isinstance(hst, str) and hst in gt_hosts:
            ingest_source = 'sensor'
    except Exception:
        pass
    hg.ingest_event(ev, source=ingest_source)

print('Total nodes:', len(hg.nodes))
# check for gt hash nodes
for h in sorted(gt_hashes):
    nid = f'hash:{h}'
    print(nid, 'in nodes?', nid in hg.nodes)
# list edges from any process to gt hashes
for src, lst in hg.adj.items():
    for (dst, et, ts, srcv, w) in lst:
        if dst.startswith('hash:gt'):
            print('edge', src, '->', dst, et, ts, srcv)

# print adjacency for host nodes in gt_hosts
for host in sorted(gt_hosts):
    hid = f'host:{host}'
    print('host', hid, 'outgoing count', len(hg.adj.get(hid, [])))
    print('sample outgoing', hg.adj.get(hid, [])[:5])

# Dump some sample nodes
print('\nSample hash nodes:')
count=0
for k in sorted(hg.nodes.keys()):
    if k.startswith('hash:'):
        print(k)
        count+=1
        if count>20:
            break
