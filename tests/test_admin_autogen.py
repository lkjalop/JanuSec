import os
import json
import asyncio
from types import SimpleNamespace
from src.api import admin_autogen as admin


def test_set_scoring_weights_and_toggle(monkeypatch, tmp_path):
    target = tmp_path / 'weights.json'
    monkeypatch.setenv('SCORING_WEIGHTS_PATH', str(target))
    monkeypatch.setenv('ADMIN_API_KEY', 'adminkey')
    fake_req = SimpleNamespace(headers={'x-api-key': 'adminkey'})
    payload = {'diversity': 0.2, 'mapping': 0.1}
    # call async handler directly
    loop = asyncio.get_event_loop()
    loop.run_until_complete(admin.set_scoring_weights(payload, fake_req))
    assert os.getenv('SCORING_WEIGHTS_JSON') is not None
    stored = json.loads(target.read_text())
    assert stored['weights']['diversity'] == 0.2
    # toggle autogen off then on
    loop.run_until_complete(admin.toggle_autogen(fake_req, False))
    assert os.getenv('INCIDENT_AUTOGEN_ENABLED','') in {'0',''}
    loop.run_until_complete(admin.toggle_autogen(fake_req, True))
    assert os.getenv('INCIDENT_AUTOGEN_ENABLED') == '1'
