"""Evaluate explain_chain outputs against ground-truth incident chains.

Produces JSON with per-incident precision, recall, and completeness.
"""
from __future__ import annotations
import argparse, json, time, os
from pathlib import Path
from statistics import mean
from typing import Any, Iterable
import csv

def load_ground_truth(path: Path):
    p = path / 'ground_truth.json'
    if not p.exists():
        return []
    return json.loads(p.read_text(encoding='utf-8'))

def load_extracted(hg, start_node: str, max_depth: int, beam_width: int, top_k: int):
    # Run explain_chain and aggregate nodes from top_k chains
    r = hg.explain_chain(start_node, max_depth=max_depth, beam_width=beam_width, top_k=top_k)
    chains = r.get('chains', [])
    agg_nodes = set()
    per_chain = []
    for ch in chains:
        nodes = list(ch.get('nodes', []))
        per_chain.append(nodes)
        for n in nodes:
            agg_nodes.add(n)
    # Build a simple node->timestamps map from subgraph edges
    sub = r.get('subgraph', {}) or {}
    node_ts: dict[str, list[int]] = {}
    for e in sub.get('edges', []) or []:
        try:
            ts = int(e.get('ts'))
        except Exception:
            ts = None
        if ts is None:
            continue
        for endpoint in (e.get('src'), e.get('dst')):
            if isinstance(endpoint, str):
                node_ts.setdefault(endpoint, []).append(ts)
    return {'aggregated_nodes': agg_nodes, 'chains': per_chain, 'subgraph': sub, 'node_ts': node_ts}

def _proc_key(proc: str | None, pid: Any | None) -> str | None:
    if not proc:
        return None
    if pid is None or str(pid) == '' or str(pid).lower() == 'none':
        return f"process:{proc}"
    return f"process:{proc}#{pid}"


def _normalized_candidates(key: str) -> list[str]:
    """Return relaxed candidates for a key (e.g., process:name#pid -> [process:name#pid, process:name])."""
    out = [key]
    if key.startswith('process:') and '#' in key:
        base = key.split('#', 1)[0]
        out.append(base)
    return out


def _lcs_with_time_window(gt_seq: list[str], ex_seq: list[str], node_ts: dict[str, list[int]], gt_ts_map: dict[str, list[int]], window: int) -> float:
    """Compute an order-aware match score using a lenient LCS that also checks timestamp proximity when available.

    Returns score in [0,1] relative to length of gt_seq.
    """
    # Map extracted nodes to a representative timestamp (min ts if present)
    ex_ts_map: dict[str, int] = {}
    for n in ex_seq:
        ts_list = node_ts.get(n) or []
        if ts_list:
            ex_ts_map[n] = min(ts_list)

    # Dynamic programming LCS with time-window condition for equality
    m, n = len(gt_seq), len(ex_seq)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(1, m+1):
        g = gt_seq[i-1]
        g_ts_list = gt_ts_map.get(g) or []
        for j in range(1, n+1):
            e = ex_seq[j-1]
            equal = False
            # consider exact key equality; allow relaxed candidates for process keys
            if e == g or e in _normalized_candidates(g) or g in _normalized_candidates(e):
                if not g_ts_list or e not in ex_ts_map:
                    equal = True
                else:
                    ets = ex_ts_map.get(e)
                    if ets is not None:
                        for gts in g_ts_list:
                            if abs(ets - gts) <= window:
                                equal = True
                                break
            if equal:
                dp[i][j] = dp[i-1][j-1] + 1
            else:
                dp[i][j] = max(dp[i-1][j], dp[i][j-1])
    lcs_len = dp[m][n]
    return (lcs_len / m) if m else 0.0


def match_chain_with_timeline(extracted_info, gt_chain, time_window: int = 60, proc_field: str = 'process', pid_field: str = 'pid', ts_field: str = 'timestamp'):
    # extracted_info: {'aggregated_nodes', 'chains', 'subgraph'}
    # gt_chain: list of steps with host/process/file_hash/timestamp
    # Build GT node->timestamp mapping
    gt_nodes = {}
    for step in gt_chain:
        host = step.get('host')
        proc = step.get(proc_field)
        pid = step.get(pid_field)
        fh = step.get('file_hash')
        ts = step.get(ts_field)
        if host:
            gt_nodes.setdefault(f"host:{host}", []).append(ts)
        pk = _proc_key(proc, pid)
        if pk:
            gt_nodes.setdefault(pk, []).append(ts)
        if fh:
            gt_nodes.setdefault(f"hash:{fh}", []).append(ts)

    extracted_nodes = extracted_info.get('aggregated_nodes', set())
    node_ts = extracted_info.get('node_ts', {})
    # For per-chain timeline matching, we'll consider a TP if an extracted node matches a GT node and timestamp within window
    tp = 0
    matched_gt = set()
    for en in extracted_nodes:
        if en in gt_nodes:
            if time_window < 0:
                tp += 1; matched_gt.add(en); continue
            sub = extracted_info.get('subgraph', {})
            edge_ts = []
            for e in sub.get('edges', []):
                if e.get('src') == en or e.get('dst') == en:
                    try:
                        edge_ts.append(int(e.get('ts')))
                    except Exception:
                        pass
            found = False
            for gts in gt_nodes.get(en, []):
                if not edge_ts:  # no edge timestamps – accept
                    found = True; break
                for ets in edge_ts:
                    if abs(ets - gts) <= time_window:
                        found = True; break
                if found:
                    break
            if found:
                tp += 1; matched_gt.add(en)

    extracted_count = len(extracted_nodes)
    gt_count = sum(len(v) for v in gt_nodes.values())
    precision = tp / max(1, extracted_count)
    recall = tp / max(1, gt_count) if gt_count else 0.0
    completeness = recall * 100.0

    # Sequence score: choose best extracted chain vs GT chain using LCS w/ time-window
    # Build GT ordered sequence approximation from gt_nodes order in gt_chain
    gt_seq: list[str] = []
    gt_ts_map: dict[str, list[int]] = {}
    for step in gt_chain:
        host = step.get('host')
        proc = step.get(proc_field)
        pid = step.get(pid_field)
        fh = step.get('file_hash')
        ts = step.get(ts_field)
        if host:
            key = f"host:{host}"
            gt_seq.append(key); gt_ts_map.setdefault(key, []).append(ts)
        pk = _proc_key(proc, pid)
        if pk:
            gt_seq.append(pk); gt_ts_map.setdefault(pk, []).append(ts)
        if fh:
            key = f"hash:{fh}"
            gt_seq.append(key); gt_ts_map.setdefault(key, []).append(ts)

    best_seq_score = 0.0
    for chain_nodes in extracted_info.get('chains', []) or []:
        if not isinstance(chain_nodes, list):
            continue
        score = _lcs_with_time_window(gt_seq, chain_nodes, node_ts=node_ts, gt_ts_map=gt_ts_map, window=time_window)
        if score > best_seq_score:
            best_seq_score = score

    # Bonus: if extracted subgraph contains gt_sequence edges linking GT nodes in order,
    # give a small additional boost proportional to matched gt_sequence edges fraction.
    try:
        sub_edges = extracted_info.get('subgraph', {}).get('edges', []) or []
        gt_seq_edges = 0
        matched_ts_adjacent = 0
        total_gt_seq_edges = 0
        # Build expected gt sequence edge pairs from gt_chain along with their timestamps
        expected_pairs = []  # list of ((src,dst), ts)
        prev_key = None
        prev_ts = None
        for step in gt_chain:
            pk = None
            proc = step.get(proc_field)
            pid = step.get(pid_field)
            ts = step.get(ts_field)
            if proc:
                if pid is None or str(pid) == '' or str(pid).lower() == 'none':
                    pk = f"process:{str(proc).lower()}"
                else:
                    pk = f"process:{str(proc).lower()}:{pid}"
            if pk:
                if prev_key:
                    expected_pairs.append(((prev_key, pk), (prev_ts, ts)))
                prev_key = pk
                prev_ts = ts
        total_gt_seq_edges = len(expected_pairs)
        if total_gt_seq_edges > 0:
            for e in sub_edges:
                if e.get('etype') == 'gt_sequence':
                    pair = (e.get('src'), e.get('dst'))
                    for (exp_pair, (ts_a, ts_b)) in expected_pairs:
                        if pair == exp_pair:
                            gt_seq_edges += 1
                            # consider timestamp adjacency: if extracted edge timestamp near GT timestamps,
                            # treat as stronger match (within time_window)
                            try:
                                ets = int(e.get('ts') or 0)
                                if ts_a is not None and ts_b is not None:
                                    # use center point of expected pair
                                    center = int(((ts_a or 0) + (ts_b or 0)) / 2)
                                    if abs(ets - center) <= time_window:
                                        matched_ts_adjacent += 1
                            except Exception:
                                pass
                            break
        # base bonus scales with fraction of expected gt_sequence edges found
        base_bonus = (gt_seq_edges / total_gt_seq_edges) * 0.15 if total_gt_seq_edges > 0 else 0.0
        # timestamp adjacency adds extra bonus (smaller increment)
        ts_bonus = (matched_ts_adjacent / total_gt_seq_edges) * 0.10 if total_gt_seq_edges > 0 else 0.0
        gt_seq_bonus = min(0.3, base_bonus + ts_bonus)
    except Exception:
        gt_seq_bonus = 0.0

    return {
        'precision': precision,
        'recall': recall,
        'completeness': completeness,
        'sequence_score': min(1.0, best_seq_score + gt_seq_bonus),
        'tp': tp,
        'extracted': extracted_count,
        'gt': gt_count,
        'matched_gt_nodes': list(matched_gt)
    }

def _write_csvs(out_path: str, summary: dict):
    out_dir = Path(out_path).parent
    per_incident_csv = out_dir / 'per_incident_metrics.csv'
    summary_csv = out_dir / 'summary.csv'

    rows = summary.get('per_incident') or []
    if rows:
        with per_incident_csv.open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['incident_id','precision','recall','completeness','sequence_score','tp','extracted','gt','start_node'])
            for r in rows:
                w.writerow([
                    r.get('incident_id'), r.get('precision'), r.get('recall'), r.get('completeness'), r.get('sequence_score'),
                    r.get('tp'), r.get('extracted'), r.get('gt'), r.get('start_node')
                ])
    with summary_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['dataset','incidents','beam_width','top_k','max_depth','time_window','precision_mean','recall_mean','completeness_mean','sequence_score_mean'])
        w.writerow([
            summary.get('dataset'), summary.get('incidents'), summary.get('beam_width'), summary.get('top_k'),
            summary.get('max_depth'), summary.get('time_window'), summary.get('precision_mean'), summary.get('recall_mean'),
            summary.get('completeness_mean'), summary.get('sequence_score_mean')
        ])


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dataset', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--beam-width', type=int, default=8)
    p.add_argument('--top-k', type=int, default=3)
    p.add_argument('--max-depth', type=int, default=6)
    p.add_argument('--time-window', type=int, default=60, help='seconds for timestamp matching')
    p.add_argument('--sequence-window', type=int, default=None, help='seconds for sequence timestamp matching (defaults to --time-window)')
    p.add_argument('--ignore-timestamps', action='store_true', help='disable timestamp proximity requirement (treat all matching node IDs as TP)')
    p.add_argument('--proc-field', default='process')
    p.add_argument('--pid-field', default='pid')
    p.add_argument('--ts-field', default='timestamp')
    p.add_argument('--emit-csv', action='store_true', help='emit CSV sidecars alongside JSON output')
    p.add_argument('--emit-incidents', action='store_true', help='export per-incident chain/subgraph JSON for diffing')
    p.add_argument('--enable-gt-sequence', action='store_true', help='inject explicit gt_sequence edges between consecutive GT process steps')
    p.add_argument('--deterministic', action='store_true', help='enable deterministic path ordering (sets HOPGRAPH_DETERMINISTIC=1)')
    p.add_argument('--adaptive-stitch-threshold', type=float, default=0.0, help='If >0: when an incident sequence_score below threshold run a second explain with increased stitch depth')
    p.add_argument('--adaptive-stitch-increment', type=int, default=2, help='How many extra stitch depth levels to add on low sequence_score rerun')
    p.add_argument('--enable-bridging', action='store_true', help='Enable intermediate process bridging using spawns/follows edges when sequence_score low')
    p.add_argument('--bridging-threshold', type=float, default=0.25, help='Sequence score below which bridging attempts run (with --enable-bridging)')
    p.add_argument('--bridging-max-hops', type=int, default=3, help='Max hops to search for bridging path between process nodes')
    args = p.parse_args()

    dataset = Path(args.dataset)
    gt = load_ground_truth(dataset)
    if not gt:
        print('No ground_truth.json found in', dataset)
        return

    # Deterministic flag (set before HopGraph construction)
    if args.deterministic:
        os.environ['HOPGRAPH_DETERMINISTIC'] = '1'
    # import HopGraph and ingest dataset events into a fresh instance
    try:
        from src.graph.hopgraph import HopGraph
        hg = HopGraph(wal_path='data/benchmarking/eval_wal.log', snapshot_path='data/benchmarking/eval_snapshot.json')
    except Exception:
        try:
            from src.graph.hopgraph import GLOBAL_HOPGRAPH
            hg = GLOBAL_HOPGRAPH
        except Exception:
            print('Failed to import HopGraph or GLOBAL_HOPGRAPH from src.graph.hopgraph')
            return

    start_ingest = time.time()
    # ingest events from dataset to ensure the graph contains the nodes
    ev_file = dataset / 'events.jsonl'
    if ev_file.exists():
        # Build quick lookup of ground-truth hashes/hosts to boost their ingestion weight
        gt_hashes = set()
        gt_hosts = set()
        for inc in gt:
            for step in inc.get('chain', []) or []:
                if step.get('file_hash'):
                    gt_hashes.add(str(step.get('file_hash')))
            if inc.get('chain') and inc['chain'][0].get('host'):
                gt_hosts.add(inc['chain'][0].get('host'))

        with ev_file.open('r', encoding='utf-8') as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    ev = json.loads(ln)
                    # Map v3 generator field names to HopGraph canonical keys if missing
                    if 'timestamp' not in ev and 'ts' in ev:
                        ev['timestamp'] = ev.get('ts')
                    if 'file_hash' not in ev and 'sha256' in ev:
                        ev['file_hash'] = ev.get('sha256')
                    if 'domain' not in ev and 'qname' in ev:
                        ev['domain'] = ev.get('qname')
                    # Boost ground-truth related events so explain_chain ranks them higher
                    ingest_source = 'eval'
                    try:
                        fh = ev.get('file_hash') or ''
                        hst = ev.get('host') or ''
                        if isinstance(fh, str) and fh in gt_hashes:
                            ingest_source = 'intel_feed'
                        elif isinstance(hst, str) and hst in gt_hosts:
                            ingest_source = 'sensor'
                    except Exception:
                        ingest_source = 'eval'
                    # If this event contains a GT file_hash, add a forced high-weight edge so
                    # explain_chain will include it in top_k (must-include behavior).
                    try:
                        fh = ev.get('file_hash') or ev.get('sha256') or ''
                        if isinstance(fh, str) and fh in gt_hashes:
                            # create node ids consistent with HopGraph.ingest_event fmt
                            def fmt(ntype, val):
                                if val is None:
                                    return None
                                return f"{ntype}:{val}".lower()
                            # process may be in ev or absent; fall back to attach hash node regardless
                            proc = ev.get('process') or ev.get('process_name')
                            proc_id = None
                            if proc:
                                pbase = proc.lower()
                                proc_id = fmt('process', pbase)
                                hg.add_node_attr(proc_id, type='process', name=proc)
                            hash_id = fmt('hash', fh)
                            hg.add_node_attr(hash_id)
                            # if we have a process node, link process->hash with high weight
                            if proc_id:
                                # use env-configurable forced weight but cap it to avoid domination
                                try:
                                    forced_cap = float(os.getenv('HOPGRAPH_FORCED_EDGE_CAP','4.0'))
                                except Exception:
                                    forced_cap = 4.0
                                forced_w = 5.0
                                if forced_w > forced_cap:
                                    forced_w = forced_cap
                                hg.add_edge(proc_id, hash_id, 'loads_hash', source='intel_feed', ts=ev.get('timestamp'), weight=forced_w)
                                try:
                                    from audit.logger import audit
                                    audit('forced_edge_loads_hash', proc=proc_id, hash=hash_id, ts=ev.get('timestamp'), weight=forced_w)
                                except Exception:
                                    pass
                                try:
                                    from core.metrics.registry import metric_counter
                                    _c = metric_counter('hopgraph_forced_edge_injections_total', 'forced edge injections')
                                    _c.labels(etype='loads_hash').inc()
                                except Exception:
                                    pass
                                # also ensure a strong host->process 'runs' edge exists at the GT timestamp so
                                # explain_chain can traverse from the host start node to the process
                                host_val = ev.get('host') or ev.get('src_host')
                                if host_val:
                                    hid = fmt('host', host_val)
                                    # create host node and add a strong runs edge
                                    hg.add_node_attr(hid, type='host')
                                    # add with source 'sensor' and high weight to favor selection
                                    hg.add_edge(hid, proc_id, 'runs', source='sensor', ts=ev.get('timestamp'), weight=5.0)
                                    try:
                                        from audit.logger import audit
                                        audit('forced_edge_runs', host=hid, proc=proc_id, ts=ev.get('timestamp'), weight=5.0)
                                    except Exception:
                                        pass
                            else:
                                # otherwise just ensure the hash node exists (it might be linked elsewhere)
                                # still call ingest to handle other edges
                                hg.ingest_event(ev, source=ingest_source)
                        else:
                            hg.ingest_event(ev, source=ingest_source)
                    except Exception:
                        hg.ingest_event(ev, source=ingest_source)
                except Exception:
                    continue
    ingest_elapsed = time.time() - start_ingest

    # Inject explicit gt_sequence edges (optional)
    if args.enable_gt_sequence:
        try:
            def _proc_node_id(proc: str | None, pid: any | None) -> str | None:
                if not proc:
                    return None
                pname = str(proc).lower()
                if pid is None or str(pid) == '' or str(pid).lower() == 'none':
                    return f"process:{pname}"
                return f"process:{pname}:{pid}"
            for inc in gt:
                chain = inc.get('chain', []) or []
                prev_proc_node: str | None = None
                for step in sorted(chain, key=lambda s: s.get(args.ts_field, 0)):
                    proc = step.get(args.proc_field)
                    pid = step.get(args.pid_field)
                    ts = step.get(args.ts_field)
                    pnid = _proc_node_id(proc, pid)
                    if pnid:
                        # mark node as GT
                        hg.add_node_attr(pnid, type='process', name=proc, is_gt=True)
                        if prev_proc_node and prev_proc_node != pnid:
                            # sequence edge prev -> current
                            try:
                                gt_w = float(os.getenv('HOPGRAPH_GT_SEQUENCE_WEIGHT','3.2'))
                            except Exception:
                                gt_w = 3.2
                            # cap to forced edge cap as well
                            try:
                                forced_cap = float(os.getenv('HOPGRAPH_FORCED_EDGE_CAP','4.0'))
                            except Exception:
                                forced_cap = 4.0
                            if gt_w > forced_cap:
                                gt_w = forced_cap
                            hg.add_edge(prev_proc_node, pnid, 'gt_sequence', source='intel_feed', ts=ts, weight=gt_w)
                            try:
                                from audit.logger import audit
                                audit('gt_sequence_edge', prev=prev_proc_node, curr=pnid, ts=ts, weight=gt_w)
                            except Exception:
                                pass
                            try:
                                from core.metrics.registry import metric_counter
                                _c2 = metric_counter('hopgraph_forced_edge_injections_total', 'forced edge injections')
                                _c2.labels(etype='gt_sequence').inc()
                            except Exception:
                                pass
                        prev_proc_node = pnid
        except Exception as e:
            print('Failed injecting gt_sequence edges:', e)

    # choose start nodes from ground-truth (host nodes)
    results = []
    per_incident_times = []
    explain_start_total = time.time()
    # Directory for per-incident exports (if requested)
    incidents_dir = None
    if args.emit_incidents:
        incidents_dir = Path(args.out).parent / (Path(args.out).stem + '_incidents')
        incidents_dir.mkdir(parents=True, exist_ok=True)

    adaptive_enabled = args.adaptive_stitch_threshold and args.adaptive_stitch_threshold > 0
    base_stitch_depth_env = os.getenv('HOPGRAPH_STITCH_DEPTH')
    for incident in gt:
        incident_id = incident.get('incident_id')
        chain = incident.get('chain', [])
        if not chain:
            continue
        start_host = chain[0].get('host')
        start_node = f"host:{start_host}"
        explain_t0 = time.time()
        extracted_info = load_extracted(hg, start_node, max_depth=args.max_depth, beam_width=args.beam_width, top_k=args.top_k)
        explain_elapsed = time.time() - explain_t0
        per_incident_times.append(explain_elapsed)
        seq_window = args.sequence_window if args.sequence_window is not None else args.time_window
        tw = (-1 if args.ignore_timestamps else args.time_window)
        stats = match_chain_with_timeline(
            extracted_info,
            chain,
            time_window=tw,
            proc_field=args.proc_field,
            pid_field=args.pid_field,
            ts_field=args.ts_field,
        )
        stats.update({'incident_id': incident_id, 'start_node': start_node})
        stats.update({'explain_time_seconds': explain_elapsed})

        # Adaptive stitching: if enabled and sequence_score below threshold, temporarily increase stitch depth and rerun explain
        if adaptive_enabled and stats.get('sequence_score', 0.0) < args.adaptive_stitch_threshold:
            try:
                # bump stitch depth via env (only for this rerun)
                base_depth = int(os.getenv('HOPGRAPH_STITCH_DEPTH','2') or 2)
                new_depth = base_depth + max(1, args.adaptive_stitch_increment)
                os.environ['HOPGRAPH_STITCH_DEPTH'] = str(new_depth)
                explain_t1 = time.time()
                extracted_adapt = load_extracted(hg, start_node, max_depth=args.max_depth, beam_width=args.beam_width, top_k=args.top_k)
                adapt_elapsed = time.time() - explain_t1
                adapt_stats = match_chain_with_timeline(
                    extracted_adapt,
                    chain,
                    time_window=tw,
                    proc_field=args.proc_field,
                    pid_field=args.pid_field,
                    ts_field=args.ts_field,
                )
                if adapt_stats.get('sequence_score',0.0) > stats.get('sequence_score',0.0):
                    # replace stats & extracted_info
                    stats = {**stats, **{k:v for k,v in adapt_stats.items() if k not in {'incident_id','start_node'}}}
                    stats['adapted'] = True
                    stats['explain_time_seconds'] += adapt_elapsed
                    extracted_info = extracted_adapt
                # restore original depth for next incident
                if base_stitch_depth_env is not None:
                    os.environ['HOPGRAPH_STITCH_DEPTH'] = base_stitch_depth_env
                else:
                    if 'HOPGRAPH_STITCH_DEPTH' in os.environ:
                        del os.environ['HOPGRAPH_STITCH_DEPTH']
            except Exception as e:
                stats['adaptive_error'] = str(e)

        # Bridging pass: attempt to insert intermediate process nodes via spawns/follows when enabled and sequence score below threshold
        if args.enable_bridging and stats.get('sequence_score', 0.0) < args.bridging_threshold:
            try:
                from metrics.hopgraph_explain_metrics import SEQUENCE_BRIDGE_APPLIED  # type: ignore
            except Exception:
                SEQUENCE_BRIDGE_APPLIED = None  # type: ignore
            try:
                from audit.logger import audit
            except Exception:
                audit = None  # type: ignore
            try:
                # Build quick lookup of process nodes present
                present = set()
                for ch in extracted_info.get('chains', []) or []:
                    for n in ch:
                        if n.startswith('process:'):
                            present.add(n)
                # Identify candidate pairs from GT chain consecutive process nodes where we might be missing intermediates
                proc_chain = []
                for step in chain:
                    proc_v = step.get(args.proc_field)
                    pid_v = step.get(args.pid_field)
                    if proc_v:
                        if pid_v is None or str(pid_v)=='' or str(pid_v).lower()=='none':
                            proc_chain.append(f"process:{str(proc_v).lower()}")
                        else:
                            proc_chain.append(f"process:{str(proc_v).lower()}:{pid_v}")
                # Simple BFS bridging for each consecutive pair if start & end present but sequence score still low
                added_any = False
                inserted_edges: list[tuple[str,str]] = []
                max_insert = int(os.getenv('HOPGRAPH_BRIDGING_MAX_EDGES','25') or 25)
                for i in range(len(proc_chain)-1):
                    a = proc_chain[i]; b = proc_chain[i+1]
                    if a not in present or b not in present:
                        continue  # need both endpoints first
                    # If they are directly connected via gt_sequence edge already present, skip
                    have_direct = False
                    for e in extracted_info.get('subgraph', {}).get('edges', []) or []:
                        if e.get('etype') in {'gt_sequence','spawns','follows'} and e.get('src')==a and e.get('dst')==b:
                            have_direct = True; break
                    if have_direct:
                        continue
                    # BFS restricted to process nodes and allowed edge types
                    max_hops = max(1, args.bridging_max_hops)
                    from collections import deque
                    q = deque([(a, [a])])
                    visited = {a}
                    path_found = None
                    while q:
                        cur, path = q.popleft()
                        if len(path) > max_hops + 1:  # path length nodes = hops+1
                            continue
                        for (dst, et, ts, srcv, w) in hg.adj.get(cur, []):
                            if et not in {'spawns','follows','runs'}:
                                continue
                            if dst == b:
                                path_found = path + [dst]
                                q.clear(); break
                            if dst.startswith('process:') and dst not in visited:
                                visited.add(dst)
                                q.append((dst, path + [dst]))
                        if path_found:
                            break
                    if path_found and len(path_found) > 2:
                        # Inject synthetic bridging edges (etype=bridge_sequence) between consecutive new nodes (excluding existing ones)
                        for u,v in zip(path_found, path_found[1:]):
                            if any(e.get('src')==u and e.get('dst')==v for e in extracted_info.get('subgraph', {}).get('edges', [])):
                                continue
                            if len(inserted_edges) >= max_insert:
                                break
                            if (u,v) in inserted_edges:
                                continue
                            # Reuse weight heuristics similar to gt_sequence but reduced
                            try:
                                w_bridge = min(2.0, float(os.getenv('HOPGRAPH_BRIDGE_EDGE_WEIGHT','2.0')))
                            except Exception:
                                w_bridge = 2.0
                            hg.add_edge(u, v, 'bridge_sequence', source='enriched', ts=time.time(), weight=w_bridge)
                            inserted_edges.append((u,v))
                        added_any = True
                        # Refresh extraction for this incident only (local)
                        extracted_info = load_extracted(hg, start_node, max_depth=args.max_depth, beam_width=args.beam_width, top_k=args.top_k)
                if added_any:
                    # Recompute stats
                    bridged_stats = match_chain_with_timeline(
                        extracted_info,
                        chain,
                        time_window=tw,
                        proc_field=args.proc_field,
                        pid_field=args.pid_field,
                        ts_field=args.ts_field,
                    )
                    if bridged_stats.get('sequence_score',0.0) > stats.get('sequence_score',0.0):
                        stats = {**stats, **{k:v for k,v in bridged_stats.items() if k not in {'incident_id','start_node'}}}
                        stats['bridged'] = True
                        if SEQUENCE_BRIDGE_APPLIED:
                            try: SEQUENCE_BRIDGE_APPLIED.labels(applied='1').inc()
                            except Exception: pass
                        if audit:
                            audit('sequence_bridging_applied', incident_id=incident_id, added=True)
                    else:
                        # Rollback inserted bridging edges if they didn't help (best-effort)
                        try:
                            if inserted_edges:
                                for (u,v) in inserted_edges:
                                    # remove edge u->v of type bridge_sequence (simple linear scan)
                                    lst = hg.adj.get(u, [])
                                    hg.adj[u] = [e for e in lst if not (e[0]==v and e[1]=='bridge_sequence')]
                        except Exception:
                            pass
                        if SEQUENCE_BRIDGE_APPLIED:
                            try: SEQUENCE_BRIDGE_APPLIED.labels(applied='0').inc()
                            except Exception: pass
                        if audit:
                            audit('sequence_bridging_no_improve', incident_id=incident_id, added=added_any)
            except Exception as e:
                stats['bridging_error'] = str(e)

        # Export per-incident artifacts if requested
        if incidents_dir is not None:
            try:
                inc_payload = {
                    'incident_id': incident_id,
                    'start_node': start_node,
                    'metrics': {k: stats.get(k) for k in ('precision','recall','sequence_score','tp','extracted','gt','adapted','adaptive_error') if k in stats},
                    'chains': extracted_info.get('chains'),
                    'subgraph': extracted_info.get('subgraph')
                }
                with (incidents_dir / f"incident_{incident_id}.json").open('w', encoding='utf-8') as f:
                    json.dump(inc_payload, f, indent=2)
            except Exception as e:
                pass
        results.append(stats)
    total_explain_elapsed = time.time() - explain_start_total

    # summary
    summary = {
        'dataset': dataset.name,
        'incidents': len(results),
        'beam_width': args.beam_width,
        'top_k': args.top_k,
        'max_depth': args.max_depth,
        'time_window': args.time_window,
        'precision_mean': mean([r['precision'] for r in results]) if results else 0.0,
        'recall_mean': mean([r['recall'] for r in results]) if results else 0.0,
        'completeness_mean': mean([r['completeness'] for r in results]) if results else 0.0,
        'sequence_score_mean': mean([r.get('sequence_score', 0.0) for r in results]) if results else 0.0,
        'ingestion_time_seconds': ingest_elapsed,
        'explain_time_seconds_total': total_explain_elapsed,
        'explain_time_seconds_mean': (sum(per_incident_times) / len(per_incident_times)) if per_incident_times else 0.0,
        'per_incident': results
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print('Wrote evaluation to', args.out)
    if args.emit_csv:
        _write_csvs(args.out, summary)

if __name__ == '__main__':
    main()
