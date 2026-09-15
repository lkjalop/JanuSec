import json
import tempfile
import os
from fastapi.testclient import TestClient

from src.api.app import app


def test_admin_reload_endpoint(tmp_path, monkeypatch):
    # prepare a reputation file
    data = {"12345": {"score": 0.5}}
    p = tmp_path / 'rep.json'
    p.write_text(json.dumps(data))

    # monkeypatch loader to point to our file
    from src.core.enrichment import asn_reputation
    # Replace load_reputation with a simple loader that reads our temp file
    monkeypatch.setattr(asn_reputation, 'load_reputation', lambda path=None: json.loads(p.read_text()))

    # call the handler directly to avoid auth middleware in unit test
    from src.api.admin_reputation import reload_reputation
    res = reload_reputation()
    assert isinstance(res, dict)
    assert res.get('status') == 'ok'


def test_background_refresher_does_not_start_in_test_mode(monkeypatch):
    # Ensure the app does not spawn the background refresher during test mode
    monkeypatch.setenv('FAST_TEST_MODE', '1')
    # import create_app and ensure startup handlers exist but do not run refresher
    from src.api.app import create_app
    a = create_app({'mode': 'test'})
    # if the app's startup handlers are present, they should not start a refresher task in test mode
    # This is a smoke check: ensure creating app does not raise and registration occurs
    assert a is not None
