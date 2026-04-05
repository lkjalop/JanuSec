from src.core.rules.schema import load_rule_from_yaml
from src.core.rules.runner import _get_node_field, _match_condition_on_node_dict, _match_condition_on_node, _resolve_join_targets
from src.core.rules import runner

r = load_rule_from_yaml('rules/examples/email_bec_chain.yaml')
print('rule.conditions', [(c.field,c.op,c.value) for c in r.conditions])

email = {'id': 'email:supplier@gmail.com|subject:Invoice payment needed', 'node_type': 'email', 'from_domain': 'supplier@gmail.com', 'subject': 'Invoice payment needed'}
art = {'id': 'artifact:account_change', 'node_type': 'artifact', 'artifact_type': 'account_change'}
nodes = [email, art]
edges = [(email['id'], art['id'], 'email_thread')]

idx = {n['id']: n for n in nodes}
adj_map = {}
for a,b,rel in edges:
    adj_map.setdefault(a, []).append({'id': b, 'rel': rel, **idx[b]})

def adj(nid):
    return adj_map.get(nid, [])

runner._get_adj_list = lambda hg: (lambda nid: adj(nid))

hg = type('HG', (), {'adj': {email['id']: [], art['id']: []}, 'nodes': {n['id']: n for n in nodes}})()

conds = [(c.field, c.value, c.op) for c in r.conditions]
print('conds', conds)

# compute anchor candidates same as run_rule
keys = list(getattr(hg, 'adj', {}).keys())
nodes_map = getattr(hg, 'nodes', {}) or {}
anchor_candidates = []
for (_f, v, op) in conds:
    if op == 'eq' and isinstance(v, str) and v in keys:
        if v not in anchor_candidates:
            anchor_candidates.append(v)
        continue
    for k in keys:
        node_dict = nodes_map.get(k)
        matched = False
        if node_dict is not None:
            matched = _match_condition_on_node_dict(node_dict, _f, op, v)
        else:
            matched = _match_condition_on_node(k, op, v)
        if matched and k not in anchor_candidates:
            anchor_candidates.append(k)

print('anchor_candidates', anchor_candidates)

for node in anchor_candidates:
    print('\n--- evaluating anchor', node)
    ok = True
    node_dict = (getattr(hg, 'nodes', {}) or {}).get(node)
    for (_f, v, op) in conds:
        matched = False
        if node_dict is not None:
            matched = _match_condition_on_node_dict(node_dict, _f, op, v)
        else:
            matched = _match_condition_on_node(node, op, v)
        print(' cond', _f, op, v, '->', matched)
        if not matched:
            ok = False
            break
    print(' all conditions ok?', ok)
    if not ok:
        continue
    adj = runner._get_adj_list(hg)
    try:
        neighbors = [e for e in adj(node)]
    except Exception:
        neighbors = []
    print(' neighbors', neighbors)
    resolved = {}
    for j in getattr(r, 'joins', []) or []:
        try:
            targets = _resolve_join_targets(hg, j, anchor=node)
        except Exception:
            targets = []
        resolved[j.get('name', 'unnamed')] = targets
    print(' resolved joins', resolved)
    print(' neighbors or joins?', bool(neighbors or any(resolved.values())))

print('\nDone')
