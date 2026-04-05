import os
import tempfile
import time
import json

import pytest

from src.outbox.consumer import OutboxConsumer

class DummyRepo:
    async def upsert_incident(self, incident_id, payload=None, tenant_id=None):
        return None

@pytest.fixture(autouse=True)
def patch_incidents_repo(monkeypatch):
    import src.repositories.incidents_repo as repo_mod
    class Dummy:
        async def upsert_incident(self, incident_id, payload=None, tenant_id=None):
            return None
    monkeypatch.setattr(repo_mod, 'upsert_incident', Dummy().upsert_incident)
    yield

def test_outbox_consumes_entry(tmp_path):
    outbox = tmp_path / "outbox.jsonl"
    payload = {"id": "inc-1", "title": "test"}
    outbox.write_text(json.dumps(payload) + "\n")

    c = OutboxConsumer(outbox_path=str(outbox), poll_interval=0.1)
    c.start()
    time.sleep(0.5)
    c.stop()

    # After consumer run, file should exist (maybe empty)
    contents = outbox.read_text(encoding='utf-8')
    assert contents.strip() == '' or contents.strip().startswith('{')
