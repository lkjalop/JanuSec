from src.core.rules.schema import load_rule_from_yaml
from src.core.rules import runner

r = load_rule_from_yaml('rules/examples/corr_office_macro_ps.yaml')
class CallableHG:
    def __init__(self):
        self.map = {'office_macro': [('host:win1','exec',{'ts':123}), ('file:ps1','created',{'ts':124})]}
    def __call__(self, n):
        return self.map.get(n, [])

hg = CallableHG()
print('rule:', r.meta.id)
print('conds:', [(c.field,c.op,c.value) for c in r.conditions])
print('joins:', r.joins)

# patch runner to use same adj as hg
# runner._get_adj_list = lambda hh: (lambda nid: hh(nid))
res = runner.run_rule(r, hg)
print('actions:', res)

# Detailed: call internals
from src.core.rules.runner import _get_adj_list, _resolve_join_targets
adj = _get_adj_list(hg)
keys = list(getattr(hg,'map').keys()) if hasattr(hg,'map') else list(getattr(hg,'adj',{}).keys())
print('keys:', keys)

anchor_candidates=[]
for c in r.conditions:
    f,v,op = c.field, c.value, c.op
    if op=='eq' and isinstance(v,str) and v in keys:
        anchor_candidates.append(v)
    else:
        for k in keys:
            from src.core.rules.runner import _match_condition_on_node
            if _match_condition_on_node(k, op, v):
                anchor_candidates.append(k)
print('anchor_candidates:', anchor_candidates)
for node in anchor_candidates:
    print('node', node)
    node_dict = (getattr(hg,'nodes',{}) or {}).get(node)
    print('node_dict', node_dict)
    neighbors = [e for e in adj(node)]
    print('neighbors', neighbors)
    print('resolve joins:', [_resolve_join_targets(hg,j,anchor=node) for j in r.joins])

