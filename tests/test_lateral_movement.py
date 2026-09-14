from __future__ import annotations

from datetime import datetime, timedelta

from src.core.detectors.lateral_movement import detect_lateral_movement


class RuntimeStub:
    def __init__(self, events):
        self.conn_events = events


def test_lateral_movement_basic():
    events = [
        {"actor": "user1", "dst_host": "srv1"},
        {"actor": "user1", "dst_host": "srv2"},
        {"actor": "user1", "dst_host": "srv3"},
        {"actor": "user1", "dst_host": "srv4"},
        {"actor": "user1", "dst_host": "srv5"},
    ]
    runtime = RuntimeStub(events)
    results = detect_lateral_movement(runtime, threshold=5)
    assert any(r["factor"] == "lateral_movement" for r in results)


def test_lateral_protocol_burst_detects_rdp():
    now = datetime.utcnow()
    events = []
    for idx, host in enumerate(["rdp-a", "rdp-b", "rdp-c"]):
        events.append(
            {
                "actor": "alice",
                "dst_host": host,
                "protocol": "rdp",
                "timestamp": (now + timedelta(seconds=idx * 60)).isoformat(),
            }
        )
    runtime = RuntimeStub(events)
    results = detect_lateral_movement(runtime, threshold=10)
    assert any(r["factor"] == "lateral_rdp_burst" for r in results), results
