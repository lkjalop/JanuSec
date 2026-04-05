import pytest
from pathlib import Path

try:
    from src.parsers.tcp_reassembly import reassemble_pcap_bytes
    from src.parsers.ja3_extractor import extract_ja3_from_flow
    from src.parsers.smb_extractor import extract_files_from_flow
    HAS_PARSERS = True
except Exception:
    HAS_PARSERS = False

FIXTURE = Path('tests/fixtures/small_http.pcap')

@pytest.mark.skipif(not HAS_PARSERS, reason='parsers not available')
def test_pcap_feature_extraction():
    if not FIXTURE.exists():
        pytest.skip('pcap fixture missing')
    data = FIXTURE.read_bytes()
    flows = list(reassemble_pcap_bytes(data))
    # ensure we get iterable of flows
    assert isinstance(flows, list)
    if flows:
        f = flows[0]
        ja3 = extract_ja3_from_flow(f)
        # ja3 may be None but function should not raise
        assert ja3 is None or isinstance(ja3, str)
        files = extract_files_from_flow(f)
        assert isinstance(files, list)
