from src.core.correlation.rules.metadata_schema import load_rule_metadata_registry, REGISTRY_FILE, RuleMetadata
import os


def test_load_rule_metadata_registry():
    assert os.path.exists(REGISTRY_FILE), 'Registry JSON should exist'
    metas = load_rule_metadata_registry()
    assert len(metas) >= 5, 'Week1 seed rules expected'
    # Ensure dynamic enrichment occurred
    for m in metas:
        if m.factors:
            assert m.stride, f'STRIDE categories not populated for {m.id}'
            assert m.dread and m.dread.risk_score is not None, f'DREAD risk missing for {m.id}'
