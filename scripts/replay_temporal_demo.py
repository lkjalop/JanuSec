"""Replay script for temporal correlation demo.

Generates a synthetic sequence that should trigger temporal patterns:
  identity:role_mutation_burst -> endpoint:lateral_exec_remote_tool -> net:flow_microcluster_exfil

Usage (PowerShell):
  python scripts/replay_temporal_demo.py
"""
from __future__ import annotations
import time, json
from typing import List, Dict

try:
    from src.graph.hopgraph_ext import GLOBAL_EXT_HOPGRAPH as HG  # type: ignore
except Exception:
    from src.graph.hopgraph import GLOBAL_HOPGRAPH as HG  # type: ignore

SEQ = [
    {'src_host':'demo-host','process':'rolesvc.exe','pid':111,'timestamp':time.time(), 'factor':'identity:role_mutation_burst'},
    {'src_host':'demo-host','process':'admincmd.exe','pid':222,'timestamp':time.time()+1, 'factor':'endpoint:lateral_exec_remote_tool'},
    {'src_host':'demo-host','process':'exfil.exe','pid':333,'dst_ip':'10.0.0.9','timestamp':time.time()+2, 'factor':'net:flow_microcluster_exfil'}
]

def attach_factor(ev: Dict[str, any]):
    # Use process node ID convention from HopGraph
    proc = ev.get('process'); pid = ev.get('pid')
    if not proc: return
    nid = f"process:{proc.lower()}:{pid}" if pid else f"process:{proc.lower()}"
    try:
        HG.add_node_attr(nid, type='process', name=proc)
        HG.add_node_factor(nid, ev['factor'])
    except Exception:
        pass

def main():
    for ev in SEQ:
        HG.ingest_event(ev)
        attach_factor(ev)
        time.sleep(0.05)
    # Explain from first process
    start = 'process:rolesvc.exe:111'
    exp = HG.explain_chain(start, max_depth=4, beam_width=5, top_k=3)
    print(json.dumps(exp, indent=2))

if __name__ == '__main__':
    main()
