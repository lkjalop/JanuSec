import os
import pytest

from src.integrations.crowdstrike_client import CrowdStrikeClient
from src.integrations.checkpoint_store import CheckpointStore

@pytest.mark.asyncio
async def test_crowdstrike_rate_limit_pagination_checkpoint(tmp_path, monkeypatch):
    fixture = 'tests/integrations/fixtures/crowdstrike_events.json'
    monkeypatch.setenv('CROWDSTRIKE_FIXTURE_PATH', fixture)
    cp = tmp_path / 'cs.json'
    monkeypatch.setenv('CROWDSTRIKE_CHECKPOINT_PATH', str(cp))

    client = CrowdStrikeClient('https://cs.example', 'id', 'secret')
    events, last = client.fetch_since()
    assert all('ts' in e for e in events)
    store = CheckpointStore(str(cp))
    assert store.load('crowdstrike:last') == str(last)
    events2, last2 = client.fetch_since()
    assert len(events2) == 0
    assert last2 == last
