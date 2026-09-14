from src.core.rules.schema import load_rule_from_yaml, DetectionRule


def test_load_example_rule():
    r = load_rule_from_yaml('rules/examples/corr_office_macro_ps.yaml')
    assert isinstance(r, DetectionRule)
    assert r.meta.name.startswith('Office Macro')
    assert len(r.conditions) >= 1
