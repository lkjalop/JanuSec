#!/usr/bin/env python
"""HopGraph Stress / Benchmark Script

Generates synthetic nodes & edges to measure:
 - Edge insertion throughput
 - Memory footprint (requires psutil optional)
 - explain_chain latency at varying depths
 - Prune latency under TTL and watermark conditions

Usage (examples):
  python scripts/hopgraph_stress.py --nodes 5000 --edges 25000
  HOPGRAPH_SNAPSHOT_EDGE_DELTA=10000 python scripts/hopgraph_stress.py --edges 50000 --snapshot-delta 5000

Environment variables:
  HOPGRAPH_SNAPSHOT_EDGE_DELTA (int) -> triggers async snapshots every N edge additions

NOTE: Designed to be safe in CI (defaults small). Use --scale large to multiply edges.
"""
from __future__ import annotations
import argparse, os, random, time, json, statistics
from typing import List

try:
    from graph.hopgraph import HopGraph
except ImportError:
    from src.graph.hopgraph import HopGraph  # fallback when run from repo root

try:
    import psutil  # type: ignore
except Exception:  # pragma: no cover
    psutil = None

EDGE_TYPES = [
    'runs','connects_to','connects_from','contacts_domain','dns_a','loads_hash','tls_ja3','tls_cert'
]
SOURCES = ['event','sensor','intel_feed','ml_model','enriched']

def build_node(ntype: str, idx: int) -> str:
    return f"{ntype}:{idx}"

def generate_edges(hg: HopGraph, num_nodes: int, num_edges: int) -> None:
    hosts = [build_node('host', i) for i in range(num_nodes//10 + 1)]
    procs = [build_node('process', i) for i in range(num_nodes)]
    domains = [build_node('domain', i) for i in range(num_nodes//5 + 1)]
    hashes = [build_node('hash', i) for i in range(num_nodes//4 + 1)]
    all_nodes = [*hosts, *procs, *domains, *hashes]
    for n in all_nodes:
        hg.add_node_attr(n, type=n.split(':',1)[0])
    start = time.time()
    for i in range(num_edges):
        et = EDGE_TYPES[i % len(EDGE_TYPES)]
        src = procs[i % len(procs)] if et != 'dns_a' else random.choice(hosts)
        if et == 'runs':
            dst = random.choice(procs)
        elif et in ('connects_to','connects_from'):
            dst = random.choice(domains)
        elif et == 'contacts_domain' or et == 'dns_a':
            dst = random.choice(domains)
        elif et == 'loads_hash':
            dst = random.choice(hashes)
        else:
            dst = random.choice(hashes)
        hg.add_edge(src, dst, et, source=random.choice(SOURCES))
    elapsed = time.time() - start
    print(f"Inserted {num_edges} edges in {elapsed:.2f}s ({num_edges/elapsed:.1f} edges/sec)")

def benchmark_explain(hg: HopGraph, sample: int = 25) -> None:
    nodes = list(hg.nodes.keys())
    if not nodes:
        print("No nodes to explain.")
        return
    picks = random.sample(nodes, min(sample, len(nodes)))
    times: List[float] = []
    for n in picks:
        t0 = time.time()
        hg.explain_chain(n, max_depth=3, beam_width=5, top_k=3)
        times.append(time.time()-t0)
    if times:
        print(f"Explain depth=3 median: {statistics.median(times)*1000:.1f} ms (n={len(times)})")


def benchmark_prune(hg: HopGraph) -> None:
    hg.edge_ttl_seconds = 0.00001  # expire almost everything
    t0 = time.time()
    hg.prune()
    elapsed = (time.time()-t0)*1000
    print(f"Prune latency: {elapsed:.2f} ms (post-prune edges={sum(len(v) for v in hg.adj.values())})")


def memory_usage():  # pragma: no cover
    if not psutil:
        return None
    p = psutil.Process()
    return p.memory_info().rss / (1024*1024)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--nodes', type=int, default=2000)
    ap.add_argument('--edges', type=int, default=10000)
    ap.add_argument('--scale', choices=['small','medium','large'], default='small')
    ap.add_argument('--snapshot-delta', type=int, default=None, help='Override HOPGRAPH_SNAPSHOT_EDGE_DELTA for run')
    args = ap.parse_args()
    scale_factor = {'small':1, 'medium':4, 'large':10}[args.scale]
    nodes = args.nodes * scale_factor
    edges = args.edges * scale_factor
    if args.snapshot_delta is not None:
        os.environ['HOPGRAPH_SNAPSHOT_EDGE_DELTA'] = str(args.snapshot_delta)
    hg = HopGraph()
    mem_before = memory_usage()
    generate_edges(hg, nodes, edges)
    mem_after = memory_usage()
    if mem_before is not None and mem_after is not None:
        print(f"Memory RSS delta: {mem_after - mem_before:.1f} MB (after={mem_after:.1f} MB)")
    benchmark_explain(hg)
    benchmark_prune(hg)
    # JSON summary for automation
    summary = {
        'nodes': len(hg.nodes),
        'edges': sum(len(v) for v in hg.adj.values()),
        'snapshot_delta': int(os.getenv('HOPGRAPH_SNAPSHOT_EDGE_DELTA','0') or 0)
    }
    print("SUMMARY:"+json.dumps(summary))

if __name__ == '__main__':
    main()
