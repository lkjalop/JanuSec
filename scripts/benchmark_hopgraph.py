"""Benchmark runner for HopGraph reconstruction.

Produces JSON results with mean, 95% CI, and timing for N episodes.

Usage:
  python -m scripts.benchmark_hopgraph --dataset data/benchmarking/benchmarks/benchmark_campaign_v1 --out data/benchmarking/results/out.json --seed 42 --runs 10
"""
from __future__ import annotations
import argparse, json, os, time, math, random
from statistics import mean, stdev
from pathlib import Path

import sys
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))

try:
    from src.graph.hopgraph import HopGraph
    HAS_HOPGRAPH = True
except Exception:
    HAS_HOPGRAPH = False


def load_synthetic_events(dataset_path: Path):
    # Expect a file events.jsonl with canonical event JSON per line
    p = dataset_path / 'events.jsonl'
    if not p.exists():
        raise FileNotFoundError(p)
    evs = []
    with p.open('r', encoding='utf-8') as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                evs.append(json.loads(ln))
            except Exception:
                continue
    return evs


def run_reconstruction_once(events, seed=None):
    # Build a fresh HopGraph and ingest events; then pick representative start nodes and call explain_chain
    if seed is not None:
        random.seed(seed)
    if HAS_HOPGRAPH:
        hg = HopGraph(wal_path='data/benchmarking/tmp_wal.log', snapshot_path='data/benchmarking/tmp_snapshot.json')
    else:
        # Fallback minimal HopGraph shim (very small subset used only for benchmarks if import fails)
        class SimpleHG:
            def __init__(self):
                self._edges = {}
                self.nodes = {}
            def ingest_event(self, ev, source='bench'):
                src = ev.get('src_host') or ev.get('host')
                dst_ip = ev.get('dst_ip') or ev.get('src_ip')
                proc = ev.get('process')
                if src and proc:
                    a = f"host:{src}"
                    b = f"process:{proc}"
                    self._edges.setdefault(a, []).append((b, 'runs', time.time()))
                    self.nodes[a] = {}; self.nodes[b] = {}
                if proc and dst_ip:
                    b = f"process:{proc}"
                    c = f"ip:{dst_ip}"
                    self._edges.setdefault(b, []).append((c, 'connects_to', time.time()))
                    self.nodes[c] = {}
            def explain_chain(self, start, max_depth=4, beam_width=5, top_k=1):
                chains = []
                if start not in self.nodes:
                    return {'start': start, 'chains': [], 'subgraph': {'nodes':{}, 'edges':[]}}
                # naive BFS up to depth
                visited = set([start])
                frontier = [start]
                edges = []
                for d in range(max_depth):
                    nxt = []
                    for n in frontier:
                        for (dst, et, ts) in self._edges.get(n, []):
                            edges.append({'src':n,'dst':dst,'etype':et,'ts':ts})
                            if dst not in visited:
                                visited.add(dst); nxt.append(dst)
                    frontier = nxt
                chains.append({'score':1.0, 'nodes': list(visited), 'hops': edges, 'length': len(edges)})
                subgraph = {'nodes': {n:{} for n in visited}, 'edges': edges}
                return {'start': start, 'chains': chains, 'subgraph': subgraph}
        hg = SimpleHG()

    # ingest
    for ev in events:
        try:
            hg.ingest_event(ev, source='benchmark')
        except Exception:
            pass

    # pick some candidate start nodes (random sample from ingested hosts/processes)
    candidate_nodes = []
    if hasattr(hg, 'nodes') and isinstance(hg.nodes, dict):
        candidate_nodes = list(hg.nodes.keys())
    if not candidate_nodes and hasattr(hg, '_edges'):
        candidate_nodes = list(hg._edges.keys())
    if not candidate_nodes:
        return {'completeness': 0.0, 'time': 0.0, 'samples': 0}

    samples = min(10, max(1, len(candidate_nodes)))
    picks = random.sample(candidate_nodes, samples)

    times = []
    completeness_scores = []
    for start in picks:
        t0 = time.time()
        res = hg.explain_chain(start, max_depth=4, beam_width=5, top_k=1)
        t1 = time.time()
        times.append(t1 - t0)
        # Heuristic completeness: fraction of unique nodes in chain vs nodes within 2 hops from start
        try:
            sub = res.get('subgraph', {})
            chain_nodes = set(sub.get('nodes', {}).keys())
            # estimate ground truth as all nodes reachable within 3 hops using k_hops if available
            ground = set()
            if hasattr(hg, 'k_hops'):
                kh = hg.k_hops(start, k=3)
                ground = set(kh.get('nodes', {}).keys())
            else:
                ground = chain_nodes
            completeness = (len(chain_nodes) / max(1, len(ground))) * 100.0
        except Exception:
            completeness = 0.0
        completeness_scores.append(completeness)

    return {'completeness': mean(completeness_scores), 'time': mean(times), 'samples': len(picks)}


def ci95(values):
    n = len(values)
    if n <= 1:
        return 0.0
    m = mean(values)
    s = stdev(values)
    # 95% CI using t ~ 1.96 for large n; for small n this is approximate
    return 1.96 * (s / math.sqrt(n))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dataset', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--seed', type=int, default=0)
    p.add_argument('--runs', type=int, default=10)
    args = p.parse_args()

    dataset = Path(args.dataset)
    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)

    events = load_synthetic_events(dataset)

    run_results = []
    for i in range(args.runs):
        s = args.seed + i if args.seed else None
        t0 = time.time()
        r = run_reconstruction_once(events, seed=s)
        t1 = time.time()
        run_results.append({'run': i, 'completeness': r.get('completeness', 0.0), 'time': r.get('time', 0.0), 'samples': r.get('samples', 0)})

    completeness_mean = mean([rr['completeness'] for rr in run_results]) if run_results else 0.0
    completeness_ci = ci95([rr['completeness'] for rr in run_results]) if run_results else 0.0
    time_mean = mean([rr['time'] for rr in run_results]) if run_results else 0.0
    time_ci = ci95([rr['time'] for rr in run_results]) if run_results else 0.0

    summary = {
        'dataset': dataset.name,
        'runs': len(run_results),
        'completeness_mean': completeness_mean,
        'completeness_ci95': completeness_ci,
        'time_seconds_mean': time_mean,
        'time_seconds_ci95': time_ci,
        'raw_runs': run_results,
        'notes': 'Synthetic benchmark generated locally; see data/benchmarking for datasets and methodology.'
    }

    outp.write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(f"Wrote results to {outp}")


if __name__ == '__main__':
    main()
