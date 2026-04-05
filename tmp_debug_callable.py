from src.core.rules.schema import load_rule_from_yaml
from src.core.rules.runner import _get_node_field, _match_condition_on_node_dict, _match_condition_on_node, _resolve_join_targets
from src.core.rules import runner

r = load_rule_from_yaml('rules/examples/corr_office_macro_ps.yaml')

class CallableHG:
    def __init__(self):
        self.map = {'office_macro': [('host:win1','exec',{'ts':123})]}
    def __call__(self, n):
        return self.map.get(n, [])

hg = CallableHG()

# replicate key extraction logic
if callable(hg):
    if hasattr(hg, 'map') and isinstance(getattr(hg, 'map'), dict):
        keys = list(getattr(hg, 'map').keys())
    else:
        try:
            keys = list(getattr(hg, 'nodes', {}).keys())
        except Exception:
            keys = []
else:
    keys = list(getattr(hg, 'adj', {}).keys())
print('keys:', keys)

conds = [(c.field, c.value, c.op) for c in r.conditions]
print('conds:', conds)

anchor_candidates = []
for (_f, v, op) in conds:
    if op == 'eq' and isinstance(v, str) and v in keys:
        if v not in anchor_candidates:
            anchor_candidates.append(v)
        continue
    for k in keys:
        node_dict = None
        matched = False
        if node_dict is not None:
            try:
                if _match_condition_on_node_dict(node_dict, _f, op, v):
                    matched = True
            except Exception:
                matched = False
        else:
            if _match_condition_on_node(k, op, v):
                matched = True
        if matched and k not in anchor_candidates:
            anchor_candidates.append(k)
print('anchor_candidates:', anchor_candidates)

# run run_rule
runner._get_adj_list = lambda hg_obj: (lambda nid: hg(hg_obj)(nid) if False else hg(nid))
print('run_rule output:', runner.run_rule(r, hg))
