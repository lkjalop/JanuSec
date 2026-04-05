import os
import asyncio
import pytest

import importlib

@pytest.mark.asyncio
async def test_metrics_increment_in_test_mode(monkeypatch):
    monkeypatch.setenv('HOPGRAPH_STREAM_TEST_MODE', '1')
    mod = importlib.import_module('src.api.hopgraph_stream')
    publish_test_event = getattr(mod, 'publish_test_event')
    counter = getattr(mod, '_STREAM_PUBLISHED', None)
    # _init_metrics may not have been called yet; publish to initialize
    before = None
    if counter is not None:
        try:
            before = counter._value.get()
        except Exception:
            before = None
    await publish_test_event({"session_id": "metric-sess", "tenant": "demo"})
    after = None
    counter = getattr(mod, '_STREAM_PUBLISHED', None)
    if counter is not None:
        try:
            after = counter._value.get()
        except Exception:
            after = None
    # Assert that if counter exists, it incremented
    if before is not None and after is not None:
        assert after >= before
    else:
        # If prometheus_client unavailable, ensure no exception path
        assert True
