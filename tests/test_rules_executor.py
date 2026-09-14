import os
import tempfile
from src.rules import executor


def test_evaluate_event_with_sample_rule(tmp_path, monkeypatch):
    # point RULES_DIR to our test fixtures
    rules_dir = os.path.join(os.getcwd(), 'tests', 'fixtures', 'rules')
    monkeypatch.setenv('RULES_DIR', rules_dir)

    rules = executor.load_rules()
    assert isinstance(rules, list)
    assert any(r.get('id') == 'sample-001' for r in rules)

    event = {'event_id': 'e1', 'message': 'This looks suspicious and needs review', 'recent': True, 'factors': ['anomaly','rare']}
    decisions = executor.evaluate_event(event, rules)
    assert isinstance(decisions, list)
    assert len(decisions) >= 1
    d = decisions[0]
    assert d.get('rule_id') in {'sample-001', 'Detect Suspicious Message'} or d.get('name') == 'Detect Suspicious Message'
    assert d.get('matched') is True
    assert d.get('score') > 0
