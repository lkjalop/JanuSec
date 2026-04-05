import asyncio
import pytest

from src.collectors.email.proofpoint_tap_collector import ProofpointTAPCollector
from src.collectors.email.mimecast_collector import MimecastCollector

class FakeResp:
    def __init__(self, status_code=200):
        self.status_code = status_code
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

class FakeAsyncClient404:
    def __init__(self):
        self.calls = []
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False
    async def post(self, url, headers=None, json=None):
        self.calls.append((url, json))
        # First: batch endpoint returns 404
        if '/ingest/batch' in url:
            return FakeResp(404)
        return FakeResp(200)

class FakeAsyncClient429Storm:
    def __init__(self, batches=2, per_events=5):
        self.calls = []
        self.batches = batches
        self.per_events = per_events
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False
    async def post(self, url, headers=None, json=None):
        self.calls.append((url, json))
        if '/ingest/batch' in url and self.batches > 0:
            self.batches -= 1
            return FakeResp(429)
        if '/ingest' in url and self.per_events > 0:
            self.per_events -= 1
            return FakeResp(429)
        return FakeResp(200)

@pytest.mark.asyncio
async def test_batch_404_fallback(monkeypatch):
    import httpx
    monkeypatch.setenv('EMAIL_INGEST_BATCH_SIZE', '5')
    c = ProofpointTAPCollector('tenantX')
    events = [{'from':'a','to':'b'} for _ in range(7)]
    monkeypatch.setattr(httpx, 'AsyncClient', lambda timeout=30: FakeAsyncClient404())
    sent = await c.forward_to_ingest(events)
    assert sent == 7

@pytest.mark.asyncio
async def test_429_storm(monkeypatch):
    import httpx
    monkeypatch.setenv('EMAIL_INGEST_BATCH_SIZE', '4')
    monkeypatch.setenv('EMAIL_INGEST_CONCURRENCY', '2')
    c = MimecastCollector('tenantY')
    events = [{'from':'a','to':'b'} for _ in range(9)]
    monkeypatch.setattr(httpx, 'AsyncClient', lambda timeout=30: FakeAsyncClient429Storm())
    sent = await c.forward_to_ingest(events)
    # Some events will be dropped due to 429s
    assert 0 < sent < 9
