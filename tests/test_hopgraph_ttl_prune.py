import os
import time

from src.graph.hopgraph import HopGraph


def test_ttl_prune_memory_only(tmp_path):
    os.environ.pop("HOPGRAPH_PERSISTENCE_ENABLED", None)
    os.environ["HOPGRAPH_EDGE_TTL_SECONDS"] = "1"  # 1 second TTL
    hg = HopGraph(wal_path=str(tmp_path/"wal.log"), snapshot_path=str(tmp_path/"snap.json"))
    t0 = time.time() - 10  # old
    hg.add_edge("host:x","process:y","runs", ts=t0)
    assert hg.adj.get("host:x")
    hg.prune(now=time.time())
    assert "host:x" not in hg.adj or not hg.adj.get("host:x")

