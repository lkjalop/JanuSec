import asyncio
import tempfile
import os
from src.core.ingest.ipfix_udp_listener import process_queue
from src.core.hopgraph import ingest_queue


def test_process_queue_creates_sessions(tmp_path, monkeypatch):
    # ensure working directory is isolated
    monkeypatch.chdir(tmp_path)

    # create an asyncio loop and run process_queue for one batch
    async def runner():
        q = asyncio.Queue()
        # push two pseudo-packets that our ipfix_adapter will treat as CSV lines
        await q.put(b'srcaddr,dstaddr,srcport,dstport,protocol,packets,bytes')
        await q.put(b'10.0.0.1,10.0.0.2,12345,80,tcp,1,100')
        # run the worker but stop after one batch
        await process_queue(q, batch_size=10, batch_timeout=0.5, stop_after_batches=1)

    asyncio.run(runner())

    sessions = ingest_queue.list_sessions()
    assert isinstance(sessions, dict)
    # at least one session file should exist
    assert len(sessions) >= 1
