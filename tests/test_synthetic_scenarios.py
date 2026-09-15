# Synthetic scenario plan tests (placeholder) - validates scenario design enumerations.

def test_synthetic_scenario_catalog():
    scenarios = {
        'lateral_movement': {
            'steps': ['multiple_hosts_same_user','proc_fanout','auth_fail_then_success'],
            'expected_factors': ['lateral_movement_candidate','graph_user_proc_burst']
        },
        'brute_force': {
            'steps': ['auth_fail_burst','eventual_success'],
            'expected_factors': ['auth_fail_burst_5m']
        },
        'data_exfiltration': {
            'steps': ['steady_outbound_growth','dns_tunnel','large_volume'],
            'expected_factors': ['exfil_volume_high','dns_tunnel_pattern']
        }
    }
    # Basic integrity checks
    for name, spec in scenarios.items():
        assert spec['steps'] and spec['expected_factors'], f"Scenario {name} incomplete"
