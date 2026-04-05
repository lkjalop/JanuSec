import os
import pytest

from src.api.hopgraph_stream_test_helper import publish_test_event


def build_minimal_session_payload(session_id: str, tenant: str = "default"):
    return {
        "session_id": session_id,
        "tenant": tenant,
        "verdict": "observe",
        "confidence": 0.5,
        "diversity": 0.0,
        "mapping": 0.0,
        "factors": ["batch_missing"],
        "graph_summary": {"nodes": 3, "edges": 2},
        "hopgraph_overlay": {
            "infrastructure": {"hosts": ["host1"], "asns": []},
            "binary": {"files": []},
            "supply_chain": {"deps": []},
        },
    }


def test_minimal_session_build_publishes_counter(monkeypatch):
    monkeypatch.setenv("HOPGRAPH_STREAM_TEST_MODE", "1")
    payload = build_minimal_session_payload("sess-abc123", tenant="default")
    ok = publish_test_event(payload)
    assert ok is True
