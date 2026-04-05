import time
from fastapi.testclient import TestClient
from src.api.app import create_app
app = create_app({'mode': 'test'})
from src.api.runtime_state import get_server_runtime_state, get_file_batch_analysis


def test_replay_diff_session_aggregation_and_bg_reprocess():
    client = TestClient(app)
    runtime = get_server_runtime_state(app)
    fb = get_file_batch_analysis(runtime)
    fb.clear()
    # create two custody events with simple structure
    e1 = {'id': 'e1', 'ts': time.time(), 'verdict': 'OBSERVE', 'confidence': 0.1, 'factors': ['f1'], 'session_id': 's1'}
    e2 = {'id': 'e2', 'ts': time.time(), 'verdict': 'SUSPECT', 'confidence': 0.8, 'factors': ['f2'], 'session_id': 's1'}
    # write to custody path
    path = runtime.file_custody_path
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf8') as fh:
        fh.write(f"{json_repr(e1)}\n")
        fh.write(f"{json_repr(e2)}\n")
    payload = {'from': time.time() - 10, 'to': time.time() + 10, 'limit': 10, 'include_sessions': True, 'persist': False, 'reprocess': True}
    r = client.post('/api/v1/replay/diff', json=payload)
    assert r.status_code == 200
    body = r.json()
    assert 'sessions' in body and isinstance(body['sessions'], dict) or isinstance(body['sessions'], list)
    # If background reprocess scheduled, runtime.replay_jobs should show last job running or done
    jobs = getattr(runtime, 'replay_jobs', [])
    assert jobs and isinstance(jobs[-1].get('status'), str)


def json_repr(obj):
    import json
    return json.dumps(obj)
