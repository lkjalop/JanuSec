import threading
import time
from src.graph.hopgraph import HopGraph


def _inserter(hg: HopGraph, start: int, count: int):
    for i in range(start, start+count):
        hg.add_edge(f'host:{i%10}', f'ip:10.0.{i%255}.{i%255}', 'connects_to', source='event', ts=time.time())


def test_concurrent_snapshot_no_exceptions():
    hg = HopGraph(wal_path='data/test_wal.log', snapshot_path='data/test_snap.json')
    # ensure clean structures
    hg.nodes.clear(); hg.adj.clear()

    threads = []
    # spawn inserter threads
    for t in range(4):
        th = threading.Thread(target=_inserter, args=(hg, t*1000, 500), daemon=True)
        threads.append(th)
        th.start()

    # while threads insert, trigger snapshot repeatedly
    for _ in range(5):
        time.sleep(0.05)
        try:
            hg.save_snapshot()
        except Exception as e:
            raise AssertionError(f'save_snapshot raised: {e}')

    for th in threads:
        th.join(timeout=2.0)

    # final parity: some edges should exist
    total_edges = sum(len(v) for v in hg.adj.values())
    assert total_edges > 0
