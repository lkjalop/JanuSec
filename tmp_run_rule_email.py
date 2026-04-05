from src.core.rules.schema import load_rule_from_yaml
from src.core.rules import runner

r = load_rule_from_yaml('rules/examples/email_bec_chain.yaml')
email = {'id': 'email:supplier@gmail.com|subject:Invoice payment needed', 'node_type': 'email', 'from_domain': 'supplier@gmail.com', 'subject': 'Invoice payment needed'}
art = {'id': 'artifact:account_change', 'node_type': 'artifact', 'artifact_type': 'account_change'}
nodes = [email, art]
edges = [(email['id'], art['id'], 'email_thread')]

# adjacency stub
idx = {n['id']: n for n in nodes}
adj_map = {}
for a,b,rel in edges:
    adj_map.setdefault(a, []).append({'id': b, 'rel': rel, **idx[b]})

def adj(nid):
    return adj_map.get(nid, [])

# patch runner's _get_adj_list
runner._get_adj_list = lambda hg: (lambda nid: adj(nid))

hg = type('HG', (), {'adj': {email['id']: [], art['id']: []}, 'nodes': {n['id']: n for n in nodes}})()

res = runner.run_rule(r, hg)
print('actions:', res)

# Also call _resolve_join_targets directly
from src.core.rules.runner import _resolve_join_targets
print('joins:', r.joins)
print('_resolve_join_targets:', _resolve_join_targets(hg, r.joins[0], anchor=email['id']))
