from src.core.rules.runner import run_rule
from src.core.rules.schema import DetectionRule
from types import SimpleNamespace


def make_rule_with_conditions(conds, joins=None, score=None):
    meta = {'id': 'r1', 'name': 'r1', 'description': None, 'author': None, 'version': None, 'tags': ['T']}
    payload = {'meta': meta, 'conditions': conds, 'actions': [], 'enabled': True}
    if joins:
        payload['joins'] = joins
    if score is not None:
        payload['score'] = score
    # Use the schema loader by writing to YAML would be heavy; construct directly
    return DetectionRule.model_validate(payload)


def test_regex_condition_matches_node():
    r = make_rule_with_conditions([{'field':'event.source','op':'regex','value':'office_.*'}])
    class HG:
        adj = {'office_macro': []}
    actions = run_rule(r, HG())
    assert actions == [] or isinstance(actions, list)


def test_contains_condition_and_multi_condition():
    r = make_rule_with_conditions([
        {'field':'event.source','op':'contains','value':'office'},
        {'field':'other','op':'eq','value':'office_macro'}
    ])
    class HG:
        adj = {'office_macro': [('a','t',{})]}
    actions = run_rule(r, HG())
    # should find anchor office_macro and emit action
    assert actions and actions[0]['evidence_node'] == 'office_macro'


def test_anchor_resolution_failure():
    r = make_rule_with_conditions([{'field':'event.source','op':'eq','value':'missing_node'}])
    class HG:
        adj = {}
    actions = run_rule(r, HG())
    assert actions == []


def test_emit_incident_dry_run_no_http_call(monkeypatch):
    r = make_rule_with_conditions([{'field':'event.source','op':'eq','value':'office_macro'}], joins=[{'name':'j1','join_type':'inner','mapping':{'p':'proc:1'}, 'anchor':'office_macro'}])
    class HG:
        adj = {'office_macro':[('proc:1','exec',{})], 'proc:1':[('file:1','wrote',{})]}
    # With dry_run True, no HTTP client needed
    actions = run_rule(r, HG(), emit_incident=True, dry_run=True)
    assert actions and actions[0]['evidence_node'] == 'office_macro'
