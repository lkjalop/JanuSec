import sys
from types import SimpleNamespace


def test_ipfix_adapter_with_mock_pyfixbuf(monkeypatch):
    # Create a fake pyfixbuf module with a decode function
    fake = SimpleNamespace()

    def fake_decode(msg):
        # pretend the binary message decodes to two records
        return [
            {
                'sourceIPv4Address': '10.0.0.1',
                'destinationIPv4Address': '10.0.0.2',
                'sourceTransportPort': '12345',
                'destinationTransportPort': '80',
                'protocolIdentifier': 6,
                'packetDeltaCount': 5,
                'octetDeltaCount': 400,
            }
        ]

    fake.decode = fake_decode
    # inject into sys.modules
    monkeypatch.setitem(sys.modules, 'pyfixbuf', fake)

    from src.core.ingest.ipfix_adapter import parse_ipfix_stream

    data = [b'fake-ipfix-bytes']
    out = list(parse_ipfix_stream(data))
    assert len(out) == 1
    rec = out[0]
    assert rec['src_ip'] == '10.0.0.1'
    assert rec['dst_ip'] == '10.0.0.2'
    assert rec['src_port'] == 12345
    assert rec['dst_port'] == 80
    assert rec['protocol'] == 6
    assert rec['packets'] == 5
    assert rec['bytes'] == 400
