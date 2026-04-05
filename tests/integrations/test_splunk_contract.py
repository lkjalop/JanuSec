import os
import json
import pytest

from src.integrations.splunk_client import SplunkClient
from src.integrations.checkpoint_store import CheckpointStore

@pytest.mark.asyncio
async def test_splunk_saved_search_pagination_and_checkpoint(tmp_path, monkeypatch):
    fixture = 'tests/integrations/fixtures/splunk_savedsearch.json'
    monkeypatch.setenv('SPLUNK_FIXTURE_PATH', fixture)
    cp = tmp_path / 'splunk.json'
    monkeypatch.setenv('SPLUNK_CHECKPOINT_PATH', str(cp))

    client = SplunkClient('https://splunk.example', token='t')
    events, last = client.fetch_since('search-1', count=1)
    # canonical fields
    assert set(events[0].keys()) == {'ts','host','user','action'}
    # checkpoint saved
    store = CheckpointStore(str(cp))
    assert store.load('splunk:last') == last
    # idempotent resume: no new events when last unchanged
    events2, last2 = client.fetch_since('search-1', count=1)
    assert len(events2) == 0
    assert last2 == last
