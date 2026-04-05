from src.core.hopgraph import ingest_queue


def test_list_and_build(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    # enqueue a couple events
    ev1 = {'type':'conn','src_ip':'10.0.0.1','dst_ip':'10.0.0.2','dst_port':22}
    ev2 = {'type':'conn','src_ip':'10.0.0.1','dst_ip':'10.0.0.3','dst_port':80}
    sid1 = ingest_queue.enqueue_event(ev1)
    sid2 = ingest_queue.enqueue_event(ev2)
    sessions = ingest_queue.list_sessions()
    assert sid1 in sessions
    assert sid2 in sessions
    summary = ingest_queue.build_session_summary(sid1, alpha=0.5)
    assert 'raw_overlap' in summary
    assert 'ewma_overlap' in summary
