import os
import pytest

from src.integrations.sentinel_client import SentinelClient
from src.integrations.checkpoint_store import CheckpointStore

@pytest.mark.asyncio
async def test_sentinel_auth_refresh_pagination_checkpoint(tmp_path, monkeypatch):
    fixture = 'tests/integrations/fixtures/sentinel_alerts.json'
    monkeypatch.setenv('SENTINEL_FIXTURE_PATH', fixture)
    cp = tmp_path / 'sentinel.json'
    monkeypatch.setenv('SENTINEL_CHECKPOINT_PATH', str(cp))

    client = SentinelClient('https://sentinel.example', 'tenant', 'id', 'secret')
    events, last = client.fetch_since()
    assert all('ts' in e for e in events)
    store = CheckpointStore(str(cp))
    assert store.load('sentinel:last') == last
    # resume should be idempotent
    events2, last2 = client.fetch_since()
    assert len(events2) == 0
    assert last2 == last
