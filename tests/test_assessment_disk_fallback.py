import os
import json
import tempfile
from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.deep_analyze_endpoints import REPORT_STORE, _get_assessment_cached


def test_get_assessment_cached_falls_back_to_disk(tmp_path, monkeypatch):
    # prepare a fake persisted assessment file
    aid = 'assessment-disk-only-123'
    base = tmp_path / 'assessments'
    orgdir = base / 'unknown' / '2025-11-22'
    orgdir.mkdir(parents=True)
    path = orgdir / f"{aid}.json"
    data = {'assessment_id': aid, 'rows': [{'ip': '1.2.3.4'}], 'status': 'pending'}
    path.write_text(json.dumps(data), encoding='utf-8')

    # point SESSION_PERSIST_DIR to our tmp dir
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(base))

    # ensure REPORT_STORE does not contain the id
    if aid in REPORT_STORE:
        REPORT_STORE.pop(aid, None)

    found = _get_assessment_cached(aid)
    assert found is not None
    assert found.get('assessment_id') == aid
    assert found.get('rows') and found['rows'][0].get('ip') == '1.2.3.4'
