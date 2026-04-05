import os
import time
import json
import glob
import shutil
from fastapi.testclient import TestClient

from src.api.app import create_app


def setup_demo_report(tmp_path):
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    data_dir = os.path.join(repo, 'data', 'assessments', 'unknown', time.strftime('%Y%m%d', time.gmtime(time.time())))
    reports_dir = os.path.join(data_dir, 'reports')
    os.makedirs(reports_dir, exist_ok=True)
    report_id = f'draft_test_{int(time.time())}'
    report = {
        'report_id': report_id,
        'org': 'unknown',
        'created_ts': int(time.time()),
        'per_row': [
            {'row_id': 'r0_aaa', 'score': 80, 'original_row': {'a':1}},
            {'row_id': 'r1_bbb', 'score': 85, 'original_row': {'a':2}},
        ]
    }
    path = os.path.join(reports_dir, f'{report_id}.json')
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(report, fh)
    return report_id, reports_dir


def test_flag_and_consume(tmp_path, monkeypatch):
    # Ensure lite init to avoid heavy optional dependencies during tests
    monkeypatch.setenv('PLATFORM_LITE_INIT', '1')
    # Import create_app after env var set
    from src.api.app import create_app, reset_rate_limit_for_tests
    reset_rate_limit_for_tests()
    app = create_app()
    # Ensure deep_analyze endpoints are mounted (module import may have been skipped in lite init)
    try:
        import importlib
        try:
            da = importlib.import_module('src.api.deep_analyze_endpoints')
            print('Imported deep_analyze_endpoints, router present:', hasattr(da, 'router'))
            try:
                app.include_router(getattr(da, 'router'))
                print('Included deep_analyze router onto app')
            except Exception as e:
                print('Failed to include deep_analyze router:', e)
        except Exception as ie:
            print('Import deep_analyze_endpoints failed:', ie)
    except Exception:
        pass
    client = TestClient(app)

    report_id, reports_dir = setup_demo_report(tmp_path)

    # debug: list routes
    routes_resp = client.get('/__debug/list_routes')
    print('ROUTES:', routes_resp.json())
    assert routes_resp.status_code == 200

    # flag two rows
    r = client.post(f'/api/v1/assessments/report/{report_id}/flag_for_retrain?row_id=r0_aaa')
    assert r.status_code == 200, f"flag r0 failed: {r.status_code} {r.text}"
    r2 = client.post(f'/api/v1/assessments/report/{report_id}/flag_for_retrain?row_id=r1_bbb')
    assert r2.status_code == 200, f"flag r1 failed: {r2.status_code} {r2.text}"

    # consume
    resp = client.post('/api/v1/assessments/admin/consume_retrain', json={'limit': 10})
    assert resp.status_code == 200
    body = resp.json()
    assert body.get('ok') is True
    processed = body.get('processed_ids') or []
    assert len(processed) >= 1

    # check training dir
    repo = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    td = os.path.join(repo, 'data', 'training')
    files = glob.glob(os.path.join(td, 'retrain_*.ndjson'))
    assert files, 'no training ndjson file created'
    # check content
    latest = sorted(files)[-1]
    with open(latest, 'r', encoding='utf-8') as fh:
        lines = fh.read().strip().splitlines()
    assert len(lines) >= 2

    # cleanup
    try:
        shutil.rmtree(os.path.join(repo, 'data', 'assessments'))
        shutil.rmtree(td)
    except Exception:
        pass
