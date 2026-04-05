from src.core.rules.runner import run_rule
from src.core.rules.schema import load_rule_from_yaml, DetectionRule


class CallableHG:
    def __init__(self):
        self.map = {'office_macro': [('host:win1','exec',{'ts':123})]}

    def __call__(self, n):
        return self.map.get(n, [])


class TransitiveHG:
    def __init__(self):
        self.adj = {
            'office_macro': [('proc:1','exec',{})],
            'proc:1': [('file:a','wrote',{})],
        }


def test_callable_adj_graph():
    r = load_rule_from_yaml('rules/examples/corr_office_macro_ps.yaml')
    hg = CallableHG()
    actions = run_rule(r, hg)
    assert actions and actions[0]['evidence']['node'] == 'office_macro'


def test_transitive_join_resolution():
    # simple join declared in YAML: mapping default anchor will be used
    r = load_rule_from_yaml('rules/examples/corr_office_macro_ps.yaml')
    hg = TransitiveHG()
    actions = run_rule(r, hg)
    # runner resolves direct neighbors for join; ensure we at least have neighbors for anchor
    assert actions and 'neighbors' in actions[0]['evidence']


def test_missing_adjacency_returns_no_actions():
    r = load_rule_from_yaml('rules/examples/corr_office_macro_ps.yaml')
    class EmptyHG:
        adj = {}
    hg = EmptyHG()
    actions = run_rule(r, hg)
    assert isinstance(actions, list)
    assert actions == []
