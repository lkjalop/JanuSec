from pathlib import Path
from src.graph.hopgraph import HopGraph
import json, time
hg = HopGraph(wal_path='data/benchmarking/eval_wal.log', snapshot_path='data/benchmarking/eval_snapshot.json')
# ingest dataset
p = Path('data/benchmarking/benchmarks/benchmark_campaign_v3_10000_aligned')
for ln in p.joinpath('events.jsonl').read_text(encoding='utf-8').splitlines():
    if not ln.strip():
        continue
    try:
        ev = json.loads(ln)
        if 'timestamp' not in ev and 'ts' in ev:
            ev['timestamp'] = ev.get('ts')
        if 'file_hash' not in ev and 'sha256' in ev:
            ev['file_hash'] = ev.get('sha256')
        if 'domain' not in ev and 'qname' in ev:
            ev['domain'] = ev.get('qname')
        hg.ingest_event(ev)
    except Exception:
        pass
# load ground truth
gt = json.loads(p.joinpath('ground_truth.json').read_text(encoding='utf-8'))
start = gt[0]['chain'][0]['host']
start_node = f'host:{start}'
print('Dumping explain for', start_node)
r = hg.explain_chain(start_node, max_depth=6, beam_width=8, top_k=10)
Path('data/benchmarking/debugs').mkdir(parents=True, exist_ok=True)
Path('data/benchmarking/debugs/explain_incident1.json').write_text(json.dumps(r, indent=2), encoding='utf-8')
print('Wrote explain dump')
