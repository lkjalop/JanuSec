import os
import pytest

from src.api.hopgraph_stream_test_helper import publish_test_event


def test_hopgraph_stream_metrics_increment_best_effort(monkeypatch):
    # Enable test mode if the module respects it
    monkeypatch.setenv("HOPGRAPH_STREAM_TEST_MODE", "1")
    ok = publish_test_event({"session_id": "test", "tenant": "default"})
    # Best-effort path: we assert the call pathway is available
    assert ok is True
