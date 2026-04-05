from src.core.rules.runner import run_rule


class FakeHG:
    def __init__(self):
        self.adj = {'office_macro': [('host:win1','exec',{'ts':123}), ('file:ps1','created',{'ts':124})]}


def test_run_rule_finds_neighbors():
    from src.core.rules.schema import load_rule_from_yaml
    r = load_rule_from_yaml('rules/examples/corr_office_macro_ps.yaml')
    hg = FakeHG()
    actions = run_rule(r, hg)
    assert isinstance(actions, list)
    assert len(actions) >= 1
    a = actions[0]
    assert a['action_type'] == 'create_incident'
    assert a['evidence_node'] == 'office_macro'
    assert len(a['evidence_neighbors']) >= 1
