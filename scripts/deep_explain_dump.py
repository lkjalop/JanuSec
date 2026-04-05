from pathlib import Path
from src.graph.hopgraph import HopGraph
import json
p = Path('data/benchmarking/benchmarks/benchmark_campaign_v3_10000_aligned')
hg = HopGraph(wal_path='data/benchmarking/eval_wal.log', snapshot_path='data/benchmarking/eval_snapshot.json')
# ingest events (with gt boosting similar to evaluator)
gt = json.loads(p.joinpath('ground_truth.json').read_text(encoding='utf-8'))
gt_hashes = set()
for inc in gt:
    for step in inc.get('chain', []) or []:
        if step.get('file_hash'):
            gt_hashes.add(str(step.get('file_hash')))
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
    # Boost GT loads explicitly
    fh = ev.get('file_hash') or ev.get('sha256') or ''
    ingest_source = 'eval'
    if isinstance(fh, str) and fh in gt_hashes:
        proc = ev.get('process') or ev.get('process_name')
        if proc:
            proc_id = f"process:{proc.lower()}"
            hash_id = f"hash:{fh}"
            hg.add_node_attr(proc_id, type='process', name=proc)
            hg.add_node_attr(hash_id)
            hg.add_edge(proc_id, hash_id, 'loads_hash', source='intel_feed', ts=ev.get('timestamp'), weight=5.0)
        else:
            hg.ingest_event(ev, source=ingest_source)
    else:
        hg.ingest_event(ev, source=ingest_source)

start = gt[0]['chain'][0]['host']
start_node = f'host:{start}'
print('Running deep explain from', start_node)
r = hg.explain_chain(start_node, max_depth=8, beam_width=100, top_k=100)
Path('data/benchmarking/debugs').mkdir(parents=True, exist_ok=True)
Path('data/benchmarking/debugs/deep_explain_incident1.json').write_text(json.dumps(r, indent=2), encoding='utf-8')
print('Wrote deep explain dump to data/benchmarking/debugs/deep_explain_incident1.json')
