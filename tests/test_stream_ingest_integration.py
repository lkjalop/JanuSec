import asyncio
import os
import tempfile
import time

import pytest
from httpx import AsyncClient

from src.api.server import app


class WorkerQueue:
    def __init__(self):
        self._q = asyncio.Queue()

    async def enqueue(self, job):
        await self._q.put(job)
        return True

    async def worker(self):
        # Process one job then exit
        job = await self._q.get()
        # Simulate processing: delete the file and mark done
        path = job.get('path')
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
        return job


@pytest.mark.asyncio
async def test_stream_ingest_integration(monkeypatch):
    q = WorkerQueue()
    # Inject into runtime_state
    import src.api.runtime_state as rs
    rs.EVENT_QUEUE = q

    # Start worker
    worker_task = asyncio.create_task(q.worker())

    from tests._helpers import default_test_headers
    headers = default_test_headers('10.2.3.4')
    headers.update({'X-API-Key': 'testkey', 'X-Tenant-Id': 'integration'})
    os.environ['INGEST_API_KEY'] = 'testkey'

    data = b'\xd4\xc3\xb2\xa1' + b'1' * 1024
    async with AsyncClient(app=app, base_url='http://test') as client:
        r = await client.post('/api/v1/ingest/stream-pcap', headers=headers, content=data)
        assert r.status_code == 200
        body = r.json()
        assert body.get('queued') is True
        session = body.get('session_id')
        path = body.get('path')

    # Wait for worker to process
    processed = await asyncio.wait_for(worker_task, timeout=5)
    assert processed.get('session_id') == session
    # file should be removed by worker
    assert not os.path.exists(path)
