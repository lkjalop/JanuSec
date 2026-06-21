from src.core.threat_modeling.factor_taxonomy import aggregate_threat_model
from src.core.mappings.mitre_stride import map_factors


def test_aggregate_threat_model_stride_and_maestro():
    cases = [
        ('net:beacon_periodic', ['information_disclosure', 'command_and_control'], ['command_and_control']),
        ('endpoint:rare_lineage', ['tampering', 'elevation'], ['execution', 'persistence']),
        ('corr_egress_exfil_pattern', ['information_disclosure', 'exfiltration'], ['exfiltration']),
        ('lane_host_pivot', ['lateral_movement', 'discovery', 'elevation'], ['lateral_movement', 'discovery']),
        ('iam:oauth_consent_grant_suspicious_app', ['spoofing', 'elevation'], ['initial_access', 'persistence']),
        ('iam:oauth_consent_excessive_scope', ['spoofing', 'elevation'], ['initial_access', 'credential_access']),
        ('iam:sp_credential_add', ['spoofing', 'elevation'], ['persistence', 'privilege_escalation']),
        ('iam:kerberoasting', ['elevation', 'information_disclosure'], ['credential_access']),
        ('iam:golden_ticket', ['spoofing', 'elevation', 'lateral_movement'], ['credential_access', 'privilege_escalation']),
        ('endpoint:wmi_lateral_exec', ['lateral_movement', 'tampering'], ['lateral_movement', 'execution']),
        ('wmi_lateral_movement', ['lateral_movement', 'tampering'], ['lateral_movement', 'execution']),
        ('exfil:cumulative_bytes_anomaly', ['information_disclosure', 'exfiltration'], ['collection', 'exfiltration']),
        ('discovery:ad_enumeration', ['information_disclosure', 'discovery'], ['discovery']),
    ]
    for factor, expected_stride, expected_maestro in cases:
        m = aggregate_threat_model([factor])
        stride = m.get('stride', {}).get('categories', [])
        maestro_phases = [p for p, _ in m.get('maestro', {}).get('phases', [])]
        for s in expected_stride:
            assert s in stride, f"{factor} expected stride {s} in {stride}"
        for p in expected_maestro:
            assert p in maestro_phases, f"{factor} expected maestro {p} in {maestro_phases}"


def test_mitre_stride_map_factors_mitre_extraction_and_stride_normalization():
    # MITRE token extraction from direct forms
    tags = set(map_factors(['mitre_TA0008', 'T1566.001']))
    assert 'mitre_TA0008' in tags
    assert 'mitre_T1566.001' in tags or 'mitre_T1566' in tags

    # Legacy factor mapped via MITRE_MAP in mitre_stride
    legacy_tags = set(map_factors(['lateral_movement_candidate']))
    assert any(t.startswith('mitre_TA') for t in legacy_tags)

    # Ensure stride canonicalization is applied: produced tags start with stride_ and contain underscore form
    stride_tags = set(map_factors(['privilege_escalation_attempt']))
    assert any(t.startswith('stride_') for t in stride_tags)
    assert any('elevation_of_privilege' in t for t in stride_tags) or any('elevation' in t for t in stride_tags)
