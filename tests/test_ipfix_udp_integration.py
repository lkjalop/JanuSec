import os
import socket
import time
import asyncio
from src.core.ingest.ipfix_udp_listener import start_ipfix_udp_listener
from src.core.hopgraph import ingest_queue


def test_udp_listener_integration(tmp_path, monkeypatch):
    # Skip by default unless env var explicitly set
    if os.environ.get('IPFIX_UDP_INTEGRATION', '0') not in ('1', 'true', 'True'):
        import pytest

        pytest.skip('UDP integration tests disabled by default')

    monkeypatch.chdir(tmp_path)

    async def runner():
        transport, protocol, task, queue = await start_ipfix_udp_listener(host='127.0.0.1', port=9999, batch_size=10, batch_timeout=0.5)
        # send a simple CSV netflow-like packet to listener
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(b'srcaddr,dstaddr,srcport,dstport,protocol,packets,bytes', ('127.0.0.1', 9999))
            sock.sendto(b'10.0.0.9,10.0.0.8,1234,80,tcp,1,50', ('127.0.0.1', 9999))
            # wait for processing
            await asyncio.sleep(1.0)
        finally:
            sock.close()
            transport.close()
            task.cancel()

    asyncio.run(runner())

    # Check sessions and metadata for exporter
    sessions = ingest_queue.list_sessions()
    assert sessions
    # check that at least one session has a .meta.json with exporter data
    found = False
    for sid, meta in sessions.items():
        meta_path = tmp_path / 'data' / 'sessions' / f'{sid}.meta.json'
        if meta_path.exists():
            found = True
            break
    assert found
