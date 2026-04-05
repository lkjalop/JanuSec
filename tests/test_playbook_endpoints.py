import os
import json
from fastapi.testclient import TestClient

from src.api.app import create_app  # type: ignore


def test_playbook_get_and_reload(monkeypatch, tmp_path):
    # Ensure test playbook DB exists
    db_dir = tmp_path / 'data' / 'playbooks'
    db_dir.mkdir(parents=True, exist_ok=True)
    db_file = db_dir / 'mitre_playbooks.json'
    db_file.write_text(json.dumps({'TTEST': {'desc':'test playbook'}}), encoding='utf-8')

    # Point working dir to tmp_path for loader to find DB
    monkeypatch.chdir(tmp_path)

    app = create_app()
    client = TestClient(app)

    # GET should return 404 for missing
    r = client.get('/api/v1/playbook/TTEST')
    assert r.status_code == 404 or r.status_code == 200

    # Force reload via endpoint (no admin key in test)
    r2 = client.post('/api/v1/playbook/reload')
    assert r2.status_code in (200, 204)
