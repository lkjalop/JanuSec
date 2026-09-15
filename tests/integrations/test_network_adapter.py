import asyncio
import pytest

from src.integrations.network_adapter import NetworkAdapter


@pytest.mark.asyncio
async def test_network_synthetic_flow_replay_and_backpressure():
    adapter = NetworkAdapter(mode="syslog", config={"max_queue": 4, "batch_size": 8})
    ok = await adapter.connect()
    assert ok

    # Enqueue 5 items into a max_queue=4; expect last one to drop
    accepted = 0
    for i in range(5):
        ev = {
            "src_ip": f"10.0.0.{i}",
            "dst_ip": "10.0.1.1",
            "src_port": 1000 + i,
            "dst_port": 80,
            "proto": "TCP",
            "ts": 1700000000 + i,
        }
        if await adapter.enqueue(ev):
            accepted += 1

    assert accepted == 4

    events, cursor = await adapter.fetch_since()
    assert len(events) == 4
    assert cursor is not None
    h = await adapter.health()
    assert h["queue_depth"] == 0
