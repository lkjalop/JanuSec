import json
from src.core.correlation.rules.metadata_schema import REGISTRY_FILE


def test_metadata_contains_minimal_fields_and_dread():
    with open(REGISTRY_FILE, 'r', encoding='utf-8') as f:
        data = json.load(f)
    assert isinstance(data, list) and len(data) > 0
    for entry in data:
        assert 'id' in entry and entry['id'], 'id missing'
        assert 'name' in entry and entry['name'], 'name missing'
        # DREAD components presence
        dread = entry.get('dread') or {}
        comp = dread.get('components') if isinstance(dread, dict) else None
    assert comp and all(k in comp for k in ('damage','reproducibility','exploitability','affected_users','discoverability')), f"DREAD components missing for {entry.get('id')}"
