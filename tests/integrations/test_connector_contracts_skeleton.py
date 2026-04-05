import json
import os
import pytest

from src.integrations.checkpoint_store import CheckpointStore

@pytest.mark.parametrize("fixture_path, key_field", [
    ("tests/integrations/fixtures/splunk_savedsearch.json", "_time"),
    ("tests/integrations/fixtures/sentinel_alerts.json", "timeGenerated"),
    ("tests/integrations/fixtures/crowdstrike_events.json", "timestamp")
])
def test_fixture_shapes_present(fixture_path, key_field):
    with open(fixture_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    # Minimal assertions that expected shape keys exist
    blob = json.dumps(data)
    assert key_field in blob

def test_checkpoint_store_roundtrip(tmp_path):
    path = os.path.join(tmp_path, 'cps.json')
    store = CheckpointStore(path)
    store.save('splunk:last', '2025-12-09T10:00:00Z')
    assert store.load('splunk:last') == '2025-12-09T10:00:00Z'
