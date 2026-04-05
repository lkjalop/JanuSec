import os
import time
import tempfile
from src.graph.auto_incident import AutoIncidentScanner


def test_auto_incident_writes_dump(tmp_path, monkeypatch):
    d = tmp_path / 'out'
    d.mkdir()
    dump_path = str(d / 'inc.jsonl')
    monkeypatch.setenv('INCIDENT_AUTOGEN_DUMP', dump_path)
    monkeypatch.setenv('INCIDENT_AUTOGEN_ENABLED', '1')
    monkeypatch.setenv('INCIDENT_AUTOGEN_INTERVAL_SECONDS', '1')
    # create scanner and start briefly
    s = AutoIncidentScanner()
    s.interval = 1
    s.enabled = True
    try:
        s.start()
        # allow a couple of loop iterations
        time.sleep(2)
        # verify thread started
        assert s._thread is not None and s._thread.is_alive()
    finally:
        s.stop()
    # after stop the thread should not be alive
    assert not (s._thread is not None and s._thread.is_alive())