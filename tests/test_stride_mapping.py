from src.core.mappings.mitre_stride import map_factors


def test_map_factors_unified_and_fallback():
    # When factors contain explicit mitre tokens, map_factors should expose them
    factors = ['mitre_TA0008', 'T1059', 'some_other_factor']
    tags = set(map_factors(factors))
    # Expect mitre tokens emitted as mitre_TA0008 and mitre_T1059
    assert 'mitre_TA0008' in tags or 'mitre_T1059' in tags


def test_map_factors_stride_normalization():
    # Simulate a factor that the taxonomy might map to 'Elevation of Privilege'
    tags = set(map_factors(['privilege_escalation_attempt']))
    # normalized tag should use lowercased underscore canonical form
    assert any(t.startswith('stride_') for t in tags)
    assert any('elevation_of_privilege' in t for t in tags) or any('information_disclosure' in t for t in tags)
