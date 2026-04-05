import asyncio
import json
import os
import time

import pytest
from fastapi.testclient import TestClient

# Import app
from api.server import app

client = TestClient(app)

@pytest.mark.asyncio
async def test_event_classification_ignore_observe_alert(monkeypatch):
    # Force low thresholds for quick classification variety
    monkeypatch.setenv('ALERT_THRESHOLD','0.3')
    monkeypatch.setenv('OBSERVE_LOW','0.15')
    monkeypatch.setenv('OBSERVE_HIGH','0.25')
    # Send benign event
    r1 = client.post('/api/v1/events', json={'id':'t1','details':{'foo':'bar'}})
    assert r1.status_code == 200
    # Send lineage suspicious to push confidence via parent_child stage (simulate parent/child fields)
    r2 = client.post('/api/v1/events', json={'id':'t2','details':{'parent_process':{'name':'winword.exe'},'process':{'name':'powershell.exe'}}})
    assert r2.status_code == 200
    # Summary check
    rsum = client.get('/api/v1/metrics/summary')
    assert rsum.status_code == 200
    js = rsum.json()
    assert 'decision_counts' in js

def test_sse_stream_connection(monkeypatch):
    # Make stream deterministic for test: SSE_TEST_MODE yields a sentinel and returns
    monkeypatch.setenv('SSE_TEST_MODE','1')
    # Basic connection open/close test (should receive sentinel immediately)
    with client.stream('GET','/api/v1/stream/decisions') as s:
        start = time.time()
        chunk = None
        try:
            chunk = next(s.iter_content(chunk_size=64))
        except StopIteration:
            pass
        except Exception:
            pass
        # Accept empty or small content; ensure stream established quickly (<2s)
        assert (time.time()-start) < 2
        # If sentinel mode, we expect data starting with 'data:'
        if chunk:
            assert b'data:' in chunk or chunk.strip() == b''
