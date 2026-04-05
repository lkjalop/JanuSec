import asyncio
import types
import json
import pytest

from src.collectors.email.proofpoint_tap_collector import ProofpointTAPCollector
from src.collectors.email.mimecast_collector import MimecastCollector
try:
    import respx
except Exception:
    respx = None

class FakeResp:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")
    def json(self):
        return self._json

class FakeAsyncClient:
    def __init__(self, responses):
        self._responses = responses
        self._calls = []
    async def __aenter__(self):
        return self
    async def __aexit__(self, exc_type, exc, tb):
        return False
    async def post(self, url, headers=None, json=None):
        self._calls.append((url, json))
        if self._responses:
            return self._responses.pop(0)
        return FakeResp(200, {})

@pytest.mark.asyncio
async def test_proofpoint_batch_chunking_and_fallback(monkeypatch):
    # Set small batch size to force chunking
    monkeypatch.setenv('EMAIL_INGEST_BATCH_SIZE', '3')
    monkeypatch.setenv('EMAIL_INGEST_CONCURRENCY', '2')
    c = ProofpointTAPCollector('tenantA')
    events = [{'from':'a@x','to':'b@x'} for _ in range(8)]
    # First chunk: 429 on batch -> fallback to per-event (simulate two 200s)
    # Second & third chunks: batch 200
    responses = [
        FakeResp(429, {}),  # batch 429 first chunk
        # per-event fallback (2 events succeed, rest succeed too)
        FakeResp(200, {}), FakeResp(200, {}), FakeResp(200, {}),
        # second chunk batch
        FakeResp(200, {}),
        # third chunk batch
        FakeResp(200, {}),
    ]

    import httpx
    if respx is None:
        monkeypatch.setattr(httpx, 'AsyncClient', lambda timeout=30: FakeAsyncClient(list(responses)))
        sent = await c.forward_to_ingest(events)
    else:
        with respx.mock(assert_all_called=False) as rs:
            rs.post('https://ingest.example/api/v1/email/ingest/batch').mock(side_effect=[httpx.Response(429), httpx.Response(200), httpx.Response(200), httpx.Response(200)])
            sent = await c.forward_to_ingest(events)
    assert sent == 8

@pytest.mark.asyncio
async def test_mimecast_batch_chunking(monkeypatch):
    monkeypatch.setenv('EMAIL_INGEST_BATCH_SIZE', '4')
    c = MimecastCollector('tenantB')
    events = [{'from':'a@x','to':'b@x'} for _ in range(9)]
    # Expect three batch posts (4,4,1)
    responses = [FakeResp(200, {}), FakeResp(200, {}), FakeResp(200, {})]
    import httpx
    if respx is None:
        fac = FakeAsyncClient(list(responses))
        monkeypatch.setattr(httpx, 'AsyncClient', lambda timeout=30: fac)
        sent = await c.forward_to_ingest(events)
    else:
        with respx.mock(assert_all_called=False) as rs:
            rs.post('https://ingest.example/api/v1/email/ingest/batch').mock(return_value=httpx.Response(200))
            sent = await c.forward_to_ingest(events)
    assert sent == 9
    # Check that batch endpoint was called thrice
    assert len(fac._calls) == 3
    assert all('/api/v1/email/ingest/batch' in u for (u, _) in fac._calls)
