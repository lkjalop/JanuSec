import os
import json
import time
from fastapi.testclient import TestClient


def test_retrain_status_and_drain(tmp_path, monkeypatch):
    # ensure lite init for test-mode helpers
    monkeypatch.setenv('PLATFORM_LITE_INIT', '1')
    from src.api.app import create_app, reset_rate_limit_for_tests
    reset_rate_limit_for_tests()
    app = create_app()
    client = TestClient(app)

    # initially empty
    r = client.get('/api/v1/admin/retrain/status')
    assert r.status_code == 200
    body = r.json()
    assert 'queue_size' in body

    # create a fake report file and flag a row
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    data_dir = os.path.join(repo, 'data', 'assessments', 'unknown', time.strftime('%Y%m%d', time.gmtime(time.time())))
    reports_dir = os.path.join(data_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    report_id = f'demo_retrain_{int(time.time())}'
    report = {
        'report_id': report_id,
        'org': 'unknown',
        'per_row': [
            {'row_id': 'rA', 'score': 42, 'original_row': {'a':1}},
        ]
    }
    path = os.path.join(reports_dir, f'{report_id}.json')
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(report, fh)

    # flag row for retrain
    r = client.post(f'/api/v1/assessments/report/{report_id}/flag_for_retrain?row_id=rA')
    assert r.status_code == 200
    out = r.json()
    assert out.get('ok') is True

    # status should now reflect queue (may be 0 until consumer runs; ensure drain works)
    r2 = client.post('/api/v1/assessments/admin/consume_retrain', json={'limit': 10})
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2.get('ok') is True
    processed = b2.get('processed_ids') or []
    # processed may be non-empty
    assert isinstance(processed, list)

    # cleanup
    try:
        import shutil
        shutil.rmtree(os.path.join(repo, 'data', 'assessments'))
        td = os.path.join(repo, 'data', 'training')
        if os.path.exists(td):
            shutil.rmtree(td)
    except Exception:
        pass
