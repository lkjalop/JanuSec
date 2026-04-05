from src.core.ingest.zeek_parser import parse_zeek_conn
from src.core.ingest.netflow_parser import parse_netflow_record
from src.core.ingest.ingest_worker import process_event_batch
from src.core.evidence.evidence_store import save_evidence_ref, get_evidence_refs


def test_zeek_and_netflow_smoke(tmp_path):
    z = parse_zeek_conn({'id.orig_h': '10.0.0.1', 'id.resp_h': '10.0.0.2', 'service': 'ssh', 'duration': '0.1', 'ts': '2025-01-01T00:00:00Z'})
    n = parse_netflow_record({'src_addr': '10.0.0.1', 'dst_addr': '10.0.0.2', 'dst_port': 22, 'bytes': 123, 'ts': '2025-01-01T00:00:00Z'})
    process_event_batch([z, n], correlate=True)
    rec = save_evidence_ref('evt-1', 'pcap', 'data/pcap/evt-1.pcap')
    refs = get_evidence_refs('evt-1')
    assert any(r['ref'] == 'data/pcap/evt-1.pcap' for r in refs)
