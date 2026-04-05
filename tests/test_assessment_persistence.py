import os
import time
import json
from src.pipeline.deep_analyze_pipeline import DEFAULT_WORKER


def test_assessment_persistence(tmp_path, monkeypatch):
    # prepare a small payload
    session_id = 'test-session-001'
    assessment_id = 'assessment-001'
    payload = {'assessment_id': assessment_id, 'org': 'unittest', 'rows': [{'process_name':'a','sha256':'00'*32}], 'options': {'auto_llm': True}}

    # ensure persistence dir points to tmp
    monkeypatch.setenv('SESSION_PERSIST_DIR', str(tmp_path))
    # start session
    DEFAULT_WORKER.start_session(session_id, payload)

    # wait for worker to complete (short sleep loop)
    for _ in range(30):
        s = DEFAULT_WORKER.status(session_id)
        if s and s.get('status') == 'completed':
            break
        if s and s.get('status') == 'failed':
            break
        time.sleep(0.1)

    s = DEFAULT_WORKER.status(session_id)
    assert s is not None
    assert s.get('status') == 'completed'

    # check persisted file
    datepart = time.strftime('%Y-%m-%d', time.gmtime(time.time()))
    path = os.path.join(str(tmp_path), 'unittest', datepart, f'{assessment_id}.json')
    assert os.path.exists(path)
    with open(path, 'r', encoding='utf-8') as fh:
        j = json.load(fh)
    assert j.get('assessment_id') == assessment_id
    assert isinstance(j.get('llm_rows', []), list)
