import pytest

from src.integrations.zeek_adapter import ZeekAdapter
from src.integrations.pcap_ingest import parse_packets


@pytest.mark.asyncio
async def test_zeek_batch_queue_and_normalization():
    z = ZeekAdapter({"max_queue": 3, "batch_size": 10})
    ok = await z.connect()
    assert ok

    # Enqueue 4 records into max_queue=3; expect last one to drop
    accepted = 0
    for i in range(4):
        rec = {
            "ts": 1700001000 + i,
            "uid": f"C{i}",
            "id.orig_h": f"192.0.2.{i}",
            "id.resp_h": "198.51.100.7",
            "id.orig_p": 4000 + i,
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
        }
        if await z.enqueue(rec):
            accepted += 1
    assert accepted == 3

    events, cursor = await z.fetch_since()
    assert len(events) == 3
    assert cursor is not None
    # Confirm normalization
    e0 = events[0]
    assert e0["src_ip"].startswith("192.0.2.")
    assert e0["dst_port"] == 443


def test_pcap_parse_packets_synthetic():
    packets = [
        {"ts": 1700002000, "src_ip": "10.1.1.1", "dst_ip": "10.1.1.2", "src_port": 1234, "dst_port": 80, "proto": "TCP", "len": 64},
        {"src_ip": "10.1.1.3", "dst_ip": "10.1.1.4", "src_port": 3456, "dst_port": 53, "proto": "UDP", "len": 60},
    ]
    out = parse_packets(packets)
    assert len(out) == 2
    assert out[0]["proto"] == "TCP"
    assert out[1]["proto"] == "UDP"
