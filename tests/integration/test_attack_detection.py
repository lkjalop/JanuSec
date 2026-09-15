from __future__ import annotations

from src.core.graph.identity_hopgraph import IdentityHopGraph
from scripts.generate_attack_scenario import make_identity_escalation


def test_identity_attack_scenario_transitions_and_explain():
    g = IdentityHopGraph()
    events = make_identity_escalation('analyst@example.com')
    for ev in events:
        g.ingest_identity_event(ev)
    snap = g.identity_snapshot('user:analyst@example.com')
    assert snap['state'] in {'Suspicious','Threat'}
    # After escalation, expect Threat
    assert g._sm.current('user:analyst@example.com') == 'Threat'
    paths = g.find_top_paths('user:analyst@example.com', limit=3)
    assert paths, 'expected risk paths'
    meta = g.explain_path(paths[0]['path'])
    assert isinstance(meta.get('mitre'), list) and meta['mitre'], 'mitre tags present'
    d = meta.get('dread') or {}
    assert 0.0 <= d.get('damage', 0.0) <= 1.0

