import sys
from types import SimpleNamespace


def test_ipfix_adapter_collector(monkeypatch):
    # Mock a pyfixbuf module with a Collector that yields mapping-like records
    class FakeRec(dict):
        def get(self, k, default=None):
            return super().get(k, default)

    class FakeCollector:
        def __init__(self):
            self._msgs = []

        def addMsg(self, msg):
            # pretend to parse and create one record per msg
            self._msgs.append(msg)

        def __iter__(self):
            for i, m in enumerate(self._msgs):
                # yield a mapping-like object
                yield FakeRec({
                    'sourceIPv4Address': f'10.0.0.{i+1}',
                    'destinationIPv4Address': f'10.0.0.{i+2}',
                    'sourceTransportPort': 1000 + i,
                    'destinationTransportPort': 2000 + i,
                    'protocolIdentifier': 17,
                    'packetDeltaCount': 1 + i,
                    'octetDeltaCount': 100 + i * 10,
                })

    fake = SimpleNamespace(Collector=FakeCollector)
    monkeypatch.setitem(sys.modules, 'pyfixbuf', fake)

    from src.core.ingest.ipfix_adapter import parse_ipfix_stream

    data = [b'msg1', b'msg2']
    out = list(parse_ipfix_stream(data))
    assert len(out) == 2
    assert out[0]['src_ip'] == '10.0.0.1'
    assert out[1]['dst_port'] == 2001
