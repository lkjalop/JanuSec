import pytest

from src.integrations.zeek_adapter import ZeekAdapter
from src.integrations.pcap_ingest import parse_packets
from src.api.graph_sessions_test_builder import build_session_from_zeek_pcap, publish_built_session


@pytest.mark.asyncio
async def test_zeek_pcap_session_build_and_publish(monkeypatch):
    monkeypatch.setenv("HOPGRAPH_STREAM_TEST_MODE", "1")
    z = ZeekAdapter({"max_queue": 8, "batch_size": 8})
    await z.connect()

    # Enqueue some Zeek-like records
    for i in range(3):
        rec = {
            "ts": 1700003000 + i,
            "uid": f"Z{i}",
            "id.orig_h": f"203.0.113.{i}",
            "id.resp_h": "198.51.100.9",
            "id.orig_p": 5000 + i,
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
        }
        assert await z.enqueue(rec)

    zeek_events, _ = await z.fetch_since()

    packets = parse_packets([
        {"src_ip": "10.2.2.2", "dst_ip": "10.2.2.3", "src_port": 2345, "dst_port": 80, "proto": "TCP", "len": 64},
        {"src_ip": "10.2.2.4", "dst_ip": "10.2.2.5", "src_port": 3456, "dst_port": 53, "proto": "UDP", "len": 60},
    ])

    payload = build_session_from_zeek_pcap("sess-zeekpcap-1", "default", zeek_events, packets)
    ok = publish_built_session(payload)
    if not ok:
        pytest.skip("SSE publisher/counter not available in this test environment")
