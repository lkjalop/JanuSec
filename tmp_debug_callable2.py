from src.core.rules.schema import load_rule_from_yaml
from src.core.rules.runner import _get_node_field, _match_condition_on_node_dict, _match_condition_on_node, _resolve_join_targets, _get_adj_list
from src.core.rules import runner

r = load_rule_from_yaml('rules/examples/corr_office_macro_ps.yaml')
class CallableHG:
    def __init__(self):
        self.map = {'office_macro': [('host:win1','exec',{'ts':123}), ('file:ps1','created',{'ts':124})]}
    def __call__(self, n):
        return self.map.get(n, [])

hg = CallableHG()
print('hg callable?', callable(hg))
adj = _get_adj_list(hg)
print('adj is hg?', adj is hg)

# anchor candidates
try:
    if callable(hg):
        if hasattr(hg, 'map') and isinstance(getattr(hg, 'map'), dict):
            keys = list(getattr(hg, 'map').keys())
        else:
            keys = list(getattr(hg, 'nodes', {}).keys())
    else:
        keys = list(getattr(hg, 'adj', {}).keys())
except Exception:
    keys = []
print('keys', keys)
conds = [(c.field, c.value, c.op) for c in r.conditions]
print('conds', conds)
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
print('anchor_candidates', anchor_candidates)

for node in anchor_candidates:
    print('\nEVALUATE ANCHOR', node)
    ok = True
    node_dict = (getattr(hg, 'nodes', {}) or {}).get(node)
    for (_f, v, op) in conds:
        matched = False
        if node_dict is not None:
            try:
                matched = _match_condition_on_node_dict(node_dict, _f, op, v)
            except Exception:
                matched = False
        else:
            matched = _match_condition_on_node(k, op, v)
        print(' cond check', _f, op, v, '->', matched)
        if not matched:
            ok = False
            break
    print(' all cond ok', ok)
    if not ok:
        continue
    try:
        neighbors = [e for e in adj(node)]
    except Exception as e:
        neighbors = []
    print(' neighbors', neighbors)
    resolved = {}
    for j in getattr(r, 'joins', []) or []:
        try:
            targets = _resolve_join_targets(hg, j, anchor=node)
        except Exception:
            targets = []
        resolved[j.get('name', 'unnamed')] = targets
    print(' resolved', resolved)
    print(' will create action?', bool(neighbors or any(resolved.values())))

print('\nDone')
