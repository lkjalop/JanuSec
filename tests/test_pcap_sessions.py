import time
from src.parsers.pcap_sessions import build_sessions_from_packets, publish_session_to_hopgraph


def test_build_sessions_basic():
    now = int(time.time())
    packets = [
        {'ts': now + 0.1, 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'src_port': 1234, 'dst_port': 80, 'proto': 'TCP', 'len': 100},
        {'ts': now + 0.2, 'src_ip': '10.0.0.2', 'dst_ip': '10.0.0.1', 'src_port': 80, 'dst_port': 1234, 'proto': 'TCP', 'len': 200},
        {'ts': now + 1.0, 'src_ip': '10.0.0.3', 'dst_ip': '10.0.0.4', 'src_port': 4000, 'dst_port': 53, 'proto': 'UDP', 'len': 60},
    ]
    sessions = build_sessions_from_packets(packets)
    assert isinstance(sessions, list)
    # should create two sessions (one for the TCP flow, one for the UDP flow)
    assert len(sessions) == 2
    sids = {s['session_id'] for s in sessions}
    assert all(len(s) >= 1 for s in sessions)


def test_publish_session_to_hopgraph(monkeypatch):
    # Create a fake hopgraph object
    called = {}

    class FakeHG:
        def add_node_attr(self, node, **attrs):
            called.setdefault('nodes', []).append((node, attrs))

        def add_edge(self, src, dst, etype, source='event', ts=None, attrs=None, weight=None):
            called.setdefault('edges', []).append((src, dst, etype, source, ts))

    fake = FakeHG()
    monkeypatch.setattr('src.parsers.pcap_sessions.GLOBAL_HOPGRAPH', fake)

    session = {
        'session_id': 'abcd1234',
        'start_ts': 100,
        'end_ts': 200,
        'src_ip': '10.0.0.1',
        'dst_ip': '10.0.0.2',
        'packet_count': 2,
        'byte_count': 300,
    }
    ok = publish_session_to_hopgraph(session, tenant='default')
    assert ok
    assert 'nodes' in called and any('pcap_session:abcd1234' in n for n, _ in called['nodes'])
    assert 'edges' in called and any('pcap_session:abcd1234' in e for e in [dst for _, dst, *_ in called['edges']])
