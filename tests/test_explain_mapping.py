from __future__ import annotations

from src.explain.mapping import map_enrichments


def test_map_enrichments_basic():
    res = map_enrichments(['ebpf:priv_escalation', 'falco_rule:shell_spawn'])
    assert 'T1548' in res['mitre']
    assert 'T1059' in res['mitre']
    assert res['dread']['damage'] >= 0.3
from src.analysis.explain_mapping import map_chain_to_threat_model


def test_map_chain_simple():
    chain = {
        'hops': [
            {'etype': 'runs', 'contrib_score': 1.0},
            {'etype': 'loads_hash', 'contrib_score': 0.5},
            {'etype': 'contacts_domain', 'contrib_score': 0.2}
        ]
    }
    out = map_chain_to_threat_model(chain)
    assert 'dread' in out and 'stride' in out and 'severity' in out
    assert out['dread']['damage'] > 0
    assert out['stride']['elevation'] is True
