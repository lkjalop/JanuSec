from src.core.rules.runner import load_rule_from_yaml, run_rule


def _make_adj_stub(nodes, edges):
    # simple adjacency callable: given a node id, return neighbor node dicts
    idx = {n['id']: n for n in nodes}
    adj = {}
    for a, b, rel in edges:
        adj.setdefault(a, []).append({'id': b, 'rel': rel, **idx[b]})
    def get_adj(node_id):
        return adj.get(node_id, [])
    return get_adj


def test_office_macro_chain_rule(tmp_path, monkeypatch):
    r = load_rule_from_yaml('rules/examples/office_macro_chain.yaml')
    # diagnostic: ensure conditions parsed
    conds = [(c.field, c.op, c.value) for c in r.conditions]
    assert any('filename' in f for (f, o, v) in conds)
    # nodes: file f1, process p1
    # Use node ids that include searchable text so run_rule's key-based matching works
    f1 = {'id': "file:invoice.docm|content:vbaProject.bin|cmdline:powershell", 'node_type': 'file', 'filename': 'invoice.docm', 'content_signatures': ['vbaProject.bin']}
    p1 = {'id': 'process:p1', 'node_type': 'process', 'cmdline': 'powershell -nop -w hidden -c ...'}
    nodes = [f1, p1]
    edges = [(f1['id'], p1['id'], 'created_process')]
    # Build hg.adj keys that include searchable strings for run_rule candidate detection
    adj = _make_adj_stub(nodes, edges)
    # keys like 'file:invoice.docm' so _match_condition_on_node can match by regex/contains
    hg_adj = {f1['id']: [], p1['id']: []}
    monkeypatch.setattr('src.core.rules.runner._get_adj_list', lambda hg: (lambda nid: adj(nid)))
    hg = type('HG', (), {'adj': hg_adj, 'nodes': {n['id']: n for n in nodes}})()
    # diagnostic: replicate anchor_candidates logic
    keys = list(getattr(hg, 'adj', {}).keys())
    anchor_candidates = []
    for (_f, v, op) in [(c.field, c.value, c.op) for c in r.conditions]:
        if op == 'eq' and v not in anchor_candidates:
            anchor_candidates.append(v)
        else:
            for k in keys:
                from src.core.rules.runner import _match_condition_on_node
                if _match_condition_on_node(k, op, v):
                    anchor_candidates.append(k)
    assert anchor_candidates, f"no anchor candidates found, keys={keys}, conds={conds}"
    res = run_rule(r, hg)
    assert isinstance(res, list)
    assert len(res) >= 1
    assert res[0]['action_type'] == 'create_incident'
    assert res[0]['rule_id'] == 'office_macro_chain'


def test_iam_priv_escalation_rule(tmp_path, monkeypatch):
    r = load_rule_from_yaml('rules/examples/iam_priv_escalation.yaml')
    ev1 = {'id': 'cloud_event:AttachUserPolicy|user:Root', 'node_type': 'cloud_event', 'eventName': 'AttachUserPolicy', 'userIdentity': {'type': 'Root'}}
    ev2 = {'id': 'cloud_event:ConsoleLogin|user:Root', 'node_type': 'cloud_event', 'eventName': 'ConsoleLogin', 'userIdentity': {'type': 'Root'}}
    nodes = [ev1, ev2]
    edges = [(ev1['id'], ev2['id'], 'same_user')]
    adj = _make_adj_stub(nodes, edges)
    hg_adj = {ev1['id']: [], ev2['id']: []}
    monkeypatch.setattr('src.core.rules.runner._get_adj_list', lambda hg: (lambda nid: adj(nid)))
    hg = type('HG', (), {'adj': hg_adj, 'nodes': {n['id']: n for n in nodes}})()
    res = run_rule(r, hg)
    assert isinstance(res, list) and res
    assert res[0]['rule_id'] == 'iam_priv_escalation'


def test_email_bec_chain_rule(tmp_path, monkeypatch):
    r = load_rule_from_yaml('rules/examples/email_bec_chain.yaml')
    email = {'id': 'email:supplier@gmail.com|subject:Invoice payment needed', 'node_type': 'email', 'from_domain': 'supplier@gmail.com', 'subject': 'Invoice payment needed'}
    art = {'id': 'artifact:account_change', 'node_type': 'artifact', 'artifact_type': 'account_change'}
    nodes = [email, art]
    edges = [(email['id'], art['id'], 'email_thread')]
    adj = _make_adj_stub(nodes, edges)
    hg_adj = {email['id']: [], art['id']: []}
    monkeypatch.setattr('src.core.rules.runner._get_adj_list', lambda hg: (lambda nid: adj(nid)))
    hg = type('HG', (), {'adj': hg_adj, 'nodes': {n['id']: n for n in nodes}})()
    res = run_rule(r, hg)
    assert isinstance(res, list) and res
    assert res[0]['rule_id'] == 'email_bec_chain'
