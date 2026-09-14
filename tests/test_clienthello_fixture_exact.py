from src.parsers.tls_helpers import parse_tls_client_hello


def test_clienthello_fixture_exact():
    p = 'tests/fixtures/clienthello_canonical.pcap'
    with open(p, 'rb') as fh:
        data = fh.read()
    # skip pcap global header (24) + packet header (16)
    payload = data[24+16:]
    sni, ja3, ja4 = parse_tls_client_hello(payload)
    assert sni == 'example.com'
    assert ja3 == '62fbcc0bb64c127aad1b26c2ef07f86e'
    assert ja4 is None
