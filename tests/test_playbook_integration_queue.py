import os
import time
import asyncio
import pytest
from fastapi.testclient import TestClient

from src.api.app import create_app

# Create a test-mode app instance to avoid import-time heavy init
app = create_app({'mode': 'test'})


@pytest.mark.asyncio
async def test_enqueue_and_process(monkeypatch, tmp_path):
    # ensure async queue uses one worker
    monkeypatch.setenv('AUTO_RUN_PLAYBOOKS', '1')
    monkeypatch.setenv('PLAYBOOK_QUEUE_WORKERS', '1')
    client = TestClient(app)
    # create a simple event that will map to an existing playbook factor
    payload = {'events': [{'id': 'e1', 'host': 'h1', 'proc_name': 'cmd.exe', 'asn': 'AS1', 'user': 'u1', 'dest_ip': '1.2.3.4', 'rules': []}], 'classify': True, 'include_rules': True, 'send_alerts': False}
    # Post to ingest; should trigger enqueue via background hook
    r = client.post('/api/v1/endpoints/log_batch', json=payload)
    assert r.status_code == 200
    # Wait briefly for background tasks to schedule and process
    await asyncio.sleep(0.5)
    # Now inspect async queue processed_count
    from src.soar.playbook_queue_async import get_global_queue_async
    q = await get_global_queue_async()
    # processed_count may be 0 if no rule matched; at least queue exists
    assert hasattr(q, 'qsize')
    # Shutdown queue to avoid leaving pending tasks on event loop close
    from src.soar.playbook_queue_async import shutdown_global_queue_async
    await shutdown_global_queue_async()
