from __future__ import annotations

from src.core.graph.identity_hopgraph import IdentityHopGraph


def test_identity_state_transitions_and_dread():
    g = IdentityHopGraph()
    # Benign login
    g.ingest_identity_event({
        'user': 'alice@corp.com',
        'src_host': 'ws-1',
        'dest_host': 'ws-1',
        'event_type': 'login',
        'action': 'login',
    })
    snap1 = g.identity_snapshot('user:alice@corp.com')
    assert snap1['state'] in {'Benign', 'Suspicious'}

    # Lateral login should make Suspicious likely
    g.ingest_identity_event({
        'user': 'alice@corp.com',
        'src_host': 'ws-1',
        'dest_host': 'server-1',
        'event_type': 'login',
        'action': 'login',
    })
    snap2 = g.identity_snapshot('user:alice@corp.com')
    assert snap2['state'] in {'Suspicious', 'Threat'}

    # Privilege escalation to a role should push to Threat
    g.ingest_identity_event({
        'user': 'alice@corp.com',
        'new_role': 'Admin',
        'action': 'assume_role',
    })
    snap3 = g.identity_snapshot('user:alice@corp.com')
    assert snap3['state'] == 'Threat'

    # Explain a path and ensure dynamic tags are present
    paths = g.find_top_paths('user:alice@corp.com', limit=3)
    assert paths, 'expected at least one path'
    meta = g.explain_path(paths[0]['path'])
    assert 'T1548' in meta['mitre'] or 'T1021' in meta['mitre']
    dread = meta['dread']
    assert isinstance(dread, dict) and 0.0 <= dread.get('damage', 0.0) <= 1.0

