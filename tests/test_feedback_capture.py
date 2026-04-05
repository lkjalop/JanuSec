import os
import json
from fastapi.testclient import TestClient
from src.api.app import app

client = TestClient(app)


def test_feedback_capture(tmp_path, monkeypatch):
    # redirect feedback dir to tmp
    fake_dir = tmp_path / 'feedback'
    fake_dir.mkdir()
    monkeypatch.setenv('PWD', str(tmp_path))
    payload = {'feedback_id': 'f1', 'report_id': 'r1', 'analyst_id': 'u1', 'correction_type': 'false_positive', 'original_value': 'THREAT', 'corrected_value': 'CLEAN', 'correction_reasoning': 'sig mismatch'}
    resp = client.post('/api/v1/assessments/feedback', json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data.get('ok') is True
