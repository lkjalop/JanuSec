import time
from src.core.ingest.ingest_worker import process_event_batch
from src.core.hopgraph import ingest_queue


def test_enqueue_and_build_summary(tmp_path, monkeypatch):
    # ensure data/sessions in workspace temp
    ingest_dir = tmp_path / 'sessions'
    monkeypatch.chdir(tmp_path)

    events = [
        {'type': 'conn', 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2', 'dst_port': 22, 'service': 'ssh'},
        {'type': 'conn', 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.3', 'dst_port': 80, 'service': 'http'},
        {'type': 'conn', 'src_ip': '10.0.0.2', 'dst_ip': '10.0.0.3', 'dst_port': 80, 'service': 'http'},
    ]

    res = process_event_batch(events, correlate=True)
    assert res['processed'] == 3
    assert isinstance(res['sessions'], list)
    # pick a session id and build a summary
    if res['sessions']:
        sid = res['sessions'][0]
        summary = ingest_queue.build_session_summary(sid, alpha=0.5)
        assert summary['session_id'] == sid
        assert 'raw_overlap' in summary
        assert 'ewma_overlap' in summary
        assert summary['event_count'] >= 1
