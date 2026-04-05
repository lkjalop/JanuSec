"""Simple demo/test runner for snapshots and eBPF example ingestion.

Usage examples:
  python -m scripts.demo_tools save-snapshot /tmp/snap.json
  python -m scripts.demo_tools load-snapshot /tmp/snap.json
  python -m scripts.demo_tools show-ebpf
"""
import sys
import json
from src.core.graph.identity_hopgraph import GLOBAL_IDENTITY_GRAPH
from src.core.event_pipeline.stages.ebpf_analysis import ebpf_analysis_stage
from src.core.event_pipeline.stages.base import StageContext
import asyncio


def save_snapshot(path: str):
    ok = GLOBAL_IDENTITY_GRAPH.save_snapshot(path)
    print(f"save_snapshot -> {ok}")


def load_snapshot(path: str):
    ok = GLOBAL_IDENTITY_GRAPH.load_snapshot(path)
    print(f"load_snapshot -> {ok}")


def show_ebpf():
    ev = {
        'source': 'falco_ebpf',
        'command': '/bin/sh -c nsenter --mount /proc/1/ns/mnt',
        'container_id': 'cid-demo',
        'syscall': 'execve',
        'rule_name': 'Container Escape Detected'
    }
    ctx = StageContext(registry=None, config=None, logger=None, state={})
    loop = asyncio.new_event_loop()
    try:
        res = loop.run_until_complete(ebpf_analysis_stage(ev, ctx))
    finally:
        loop.close()
    print(json.dumps({'factors': res.factors}, indent=2))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == 'save-snapshot' and len(sys.argv) >= 3:
        save_snapshot(sys.argv[2])
    elif cmd == 'load-snapshot' and len(sys.argv) >= 3:
        load_snapshot(sys.argv[2])
    elif cmd == 'show-ebpf':
        show_ebpf()
    else:
        print('unknown command')
        print(__doc__)
