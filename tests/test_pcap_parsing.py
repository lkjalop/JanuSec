import pytest

try:
    from scapy.all import Ether, IP, TCP, wrpcap
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

from src.parsers.pcap_parser import parse_pcap_bytes


@pytest.mark.skipif(not SCAPY_OK, reason='scapy not installed')
def test_parse_simple_pcap(tmp_path):
    # Build a simple TCP packet with an HTTP GET payload
    pkt = Ether()/IP(dst='10.0.0.1', src='10.0.0.2')/TCP(sport=12345, dport=80)/b'GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: pytest\r\n\r\n'
    pcap_file = tmp_path / 'test.pcap'
    wrpcap(str(pcap_file), [pkt])
    data = pcap_file.read_bytes()
    rows = parse_pcap_bytes(data)
    assert isinstance(rows, list)
    assert len(rows) >= 1
    r = rows[0]
    assert r['src'] == '10.0.0.2'
    assert r['dst'] == '10.0.0.1'
    assert r['raw_payload_len'] > 0
