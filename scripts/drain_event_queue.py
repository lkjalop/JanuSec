#!/usr/bin/env python3
"""Simple in-process consumer to drain runtime EVENT_QUEUE and call ingest paths.
Use for local dev to process events enqueued by TestClient HTTP handlers.
"""
import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.api import runtime_state
from src.graph.hopgraph import GLOBAL_HOPGRAPH


async def _consume_once(q, limit=1000):
    consumed = 0
    for _ in range(limit):
        ev = await q.dequeue(timeout=0.1)
        if not ev:
            break
        # If event looks like normalized zeek event -> call ingest_event
        try:
            if isinstance(ev, dict):
                try:
                    from src.core.graph.hopgraph_utils import safe_upsert_node
                except Exception:
                    safe_upsert_node = None
                try:
                    if safe_upsert_node is not None and ev.get('type') == 'file_hash' and ev.get('id'):
                        safe_upsert_node(GLOBAL_HOPGRAPH, 'file_hash', ev.get('id'), attrs=ev.get('attrs') or {}, source='stream_ingest')
                    else:
                        GLOBAL_HOPGRAPH.ingest_event(ev, source='stream_ingest')
                except Exception:
                    try:
                        GLOBAL_HOPGRAPH.ingest_event(ev, source='stream_ingest')
                    except Exception:
                        pass
        except Exception:
            pass
        consumed += 1
    return consumed


def main(limit=1000):
    q = runtime_state.EVENT_QUEUE
    loop = asyncio.get_event_loop()
    n = loop.run_until_complete(_consume_once(q, limit=limit))
    print('Consumed', n)


if __name__ == '__main__':
    main()
