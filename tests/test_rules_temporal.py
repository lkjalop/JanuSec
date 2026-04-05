import os
import time
from src.rules import executor


def test_temporal_count_rule(monkeypatch):
    rules_dir = os.path.join(os.getcwd(), 'tests', 'fixtures', 'rules')
    monkeypatch.setenv('RULES_DIR', rules_dir)
    rules = executor.load_rules()
    assert any(r.get('id') == 'temporal-001' for r in rules)

    now = int(time.time())
    # Build history of failed_login events within 60s
    history = [
        {'event_type': 'failed_login', 'ts': now - 10},
        {'event_type': 'failed_login', 'ts': now - 20},
        {'event_type': 'failed_login', 'ts': now - 30},
        {'event_type': 'failed_login', 'ts': now - 40},
    ]
    event = {'event_id': 'e2', 'history': history}
    decisions = executor.evaluate_event(event, rules)
    assert isinstance(decisions, list)
    assert len(decisions) >= 1
    d = decisions[0]
    assert d.get('rule_id') == 'temporal-001'
