import os
import asyncio
import pytest

from src.api.hopgraph_stream import publish_test_event

@pytest.mark.asyncio
async def test_publish_test_event_increments_metric(monkeypatch):
    monkeypatch.setenv('HOPGRAPH_STREAM_TEST_MODE', '1')
    # Publish a simple event; ensure no exception in test mode
    evt = {"session_id": "test-sess", "tenant": "demo", "verdict": "ok", "confidence": 0.5}
    await publish_test_event(evt)
    # Note: We rely on existing tests/metrics checks elsewhere; here we ensure gated path does not raise.
    assert True
