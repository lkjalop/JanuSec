import os

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.deep_analyze_endpoints import REPORT_STORE


def _create_assessment(client: TestClient) -> str:
    payload = {
        'rows': [
            {'ip': '8.8.4.4', 'file_hash': 'a1'},
            {'ip': '8.8.8.8', 'file_hash': 'a2'},
        ],
        'options': {'auto_llm': True},
    }
    resp = client.post('/api/v1/assessments/deep_analyze', json=payload)
    assert resp.status_code == 200
    body = resp.json()
    aid = body.get('assessment_id')
    if not aid and REPORT_STORE:
        aid = next(iter(REPORT_STORE.keys()))
    assert aid
    return aid


def test_llm_enqueue_progress_and_abort():
    os.environ['LLM_MOCK'] = '1'
    app = create_app()
    client = TestClient(app)
    assessment_id = _create_assessment(client)
    enqueue_resp = client.post(f'/api/v1/assessments/{assessment_id}/llm/enqueue', json={'limit': 1})
    assert enqueue_resp.status_code == 200, f"enqueue failed: {enqueue_resp.status_code} {enqueue_resp.text}"
    data = enqueue_resp.json()
    assert data['enqueued'] >= 0

    progress = client.get(f'/api/v1/assessments/{assessment_id}/llm/progress')
    assert progress.status_code == 200
    progress_body = progress.json()
    assert 'queued' in progress_body

    rows_map = progress_body.get('rows') or {}
    if rows_map:
        any_index = next(iter(rows_map.keys()))
        status_resp = client.get(f'/api/v1/assessments/{assessment_id}/llm/status/{any_index}')
        assert status_resp.status_code == 200
        status_data = status_resp.json()
        assert status_data['row_index'] == int(any_index)

    abort_resp = client.post(f'/api/v1/assessments/{assessment_id}/llm/abort')
    assert abort_resp.status_code == 200
    assert 'aborted' in abort_resp.json()
import os

from fastapi.testclient import TestClient

from src.api.app import create_app
from src.api.deep_analyze_endpoints import REPORT_STORE


def _create_assessment(client: TestClient) -> str:
    payload = {
        'rows': [
            {'ip': '8.8.4.4', 'file_hash': 'a1'},
            {'ip': '8.8.8.8', 'file_hash': 'a2'},
        ],
        'options': {'auto_llm': True},
    }
    resp = client.post('/api/v1/assessments/deep_analyze', json=payload)
    assert resp.status_code == 200
    body = resp.json()
    aid = body.get('assessment_id')
    if not aid and REPORT_STORE:
        aid = next(iter(REPORT_STORE.keys()))
    assert aid
    import os

    from fastapi.testclient import TestClient

    from src.api.app import create_app
    from src.api.deep_analyze_endpoints import REPORT_STORE


    def _create_assessment(client: TestClient) -> str:
        payload = {
            'rows': [
                {'ip': '8.8.4.4', 'file_hash': 'a1'},
                {'ip': '8.8.8.8', 'file_hash': 'a2'},
            ],
            'options': {'auto_llm': True},
        }
        resp = client.post('/api/v1/assessments/deep_analyze', json=payload)
        assert resp.status_code == 200
        body = resp.json()
        aid = body.get('assessment_id')
        if not aid and REPORT_STORE:
            aid = next(iter(REPORT_STORE.keys()))
        assert aid
        return aid


    def test_llm_enqueue_progress_and_abort():
        os.environ['LLM_MOCK'] = '1'
        app = create_app()
        client = TestClient(app)
        assessment_id = _create_assessment(client)

        enqueue_resp = client.post(f'/api/v1/assessments/{assessment_id}/llm/enqueue', json={'limit': 1})
        assert enqueue_resp.status_code == 200
        data = enqueue_resp.json()
        assert data['enqueued'] >= 0

        progress = client.get(f'/api/v1/assessments/{assessment_id}/llm/progress')
        assert progress.status_code == 200
        progress_body = progress.json()
        assert 'queued' in progress_body

        rows_map = progress_body.get('rows') or {}
        if rows_map:
            any_index = next(iter(rows_map.keys()))
            status_resp = client.get(f'/api/v1/assessments/{assessment_id}/llm/status/{any_index}')
            assert status_resp.status_code == 200
            status_data = status_resp.json()
            assert status_data['row_index'] == int(any_index)

        abort_resp = client.post(f'/api/v1/assessments/{assessment_id}/llm/abort')
        assert abort_resp.status_code == 200
        assert 'aborted' in abort_resp.json()
