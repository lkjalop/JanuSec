import os
import json
import tempfile

from src.api import admin_scoring


def test_weights_persist_and_load(monkeypatch, tmp_path):
    p = tmp_path / 'weights.json'
    monkeypatch.setenv('SCORING_WEIGHTS_PATH', str(p))
    # set admin api key and provide header via request simulation
    monkeypatch.setenv('ADMIN_API_KEY', 'adminkey')
    # Build payload
    payload = {'weights': {'diversity': 0.07, 'mapping': 0.05}}
    class DummyRequest:
        def __init__(self):
            self.headers = {'x-api-key': 'adminkey'}
    req = DummyRequest()
    res = None
    # Call update
    res =  asyncio_run(admin_scoring.update_weights(payload, req))
    assert res['version'] == 1
    # Call get
    got = asyncio_run(admin_scoring.get_weights())
    assert got['version'] == 1
    assert got['weights']['diversity'] == 0.07


def asyncio_run(coro):
    import asyncio
    return asyncio.get_event_loop().run_until_complete(coro)
