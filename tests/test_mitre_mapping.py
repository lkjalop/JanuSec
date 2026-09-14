from core.mappings.mitre_stride import map_factors


def test_mitre_stride_mapping_basic():
    input_factors = ['lateral_movement_candidate','graph_user_proc_burst','dns_tunnel_pattern']
    tags = map_factors(input_factors)
    assert 'mitre_TA0008' in tags  # lateral movement
    assert 'mitre_TA0002' in tags  # user proc burst -> execution
    assert 'mitre_TA0011' in tags  # dns tunnel
    # stride mapping
    assert 'stride_information_disclosure' in tags
    assert 'stride_elevation_of_privilege' in tags
