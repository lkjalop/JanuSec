from src.core.reporting.factor_descriptions import load_factor_descriptions


def test_factor_descriptions_ext_contains_new_factors():
    desc = load_factor_descriptions()
    # Spot-check a few newly added factors across domains
    assert 'identity:password_spray_slow_burn' in desc
    assert 'endpoint:edr_uninstall_or_tamper_flow' in desc
    assert 'net:quic_fingerprint_novelty' in desc
    assert 'cloud:logging_gap_or_disable' in desc
    assert 'remote:ssh_agent_forwarding_misuse' in desc
    assert 'api:graphql_introspection_exposed' in desc
    assert 'data:staging_table_exfil_flow' in desc
    assert 'email:smtp_auth_residential_asn' in desc

