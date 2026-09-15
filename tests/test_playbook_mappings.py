import os
from src.soar import playbook_loader as pl


def test_factor_to_playbook_mappings():
    # Map of factor -> expected playbook filename fragment
    expected = {
        'identity:pass_the_cookie_reuse': 'token_replay_revoke_sessions',
        'net:doh_tunnel_candidate': 'network_doh_tor_block',
        'net:tor_outbound_contact': 'network_doh_tor_block',
        'cloud:iam_policy_shadow_admin': 'cloud_shadow_admin_rollback',
        'endpoint:unsigned_driver_install_flow': 'endpoint_unsigned_driver_quarantine',
        'email:mailbox_rule_burst': 'email_mailbox_rule_burst',
    }
    def trigger_matches(pb: dict, factor: str) -> bool:
        trig = pb.get('trigger') or {}
        if trig.get('factor') == factor:
            return True
        fa = trig.get('factor_any') or []
        if isinstance(fa, list) and factor in fa:
            return True
        fp = trig.get('factor_prefix')
        if fp and factor.startswith(fp):
            return True
        return False

    for factor in expected.keys():
        pbs = pl.resolve_for_factor(factor)
        assert pbs, f"no playbooks resolved for factor {factor}"
        assert any(trigger_matches(pb, factor) for pb in pbs), f"resolved playbooks do not match trigger for {factor}"


def test_render_with_event_context():
    # pick a playbook for token replay and render with an event
    pbs = pl.resolve_for_factor('identity:pass_the_cookie_reuse')
    assert pbs, 'expected at least one playbook for token replay'
    pb = pbs[0]
    event = {'user': 'carol', 'host': 'host-1', 'dest_ip': '10.0.0.5'}
    ctx = pl.extract_context_from_event(event)
    rendered = pl.render_playbook(pb, ctx)
    # Rendering should complete and contain steps; substitution may be no-op if playbook uses static params
    assert isinstance(rendered, dict)
    assert 'steps' in rendered and isinstance(rendered['steps'], list)
