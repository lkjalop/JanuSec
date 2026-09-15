from core.threat_modeling.scenario_engine import ENGINE


def test_scenario_engine_basic_observed():
    factors = [
        'dns:tunnel_suspected',
        'net:beacon_periodic',
        'ssl:ja3_rare'
    ]
    results = ENGINE.evaluate(factors)
    # Ensure DNS tunneling scenario appears
    dns = [r for r in results if r['id'] == 'SCN-DNS-EXFIL']
    assert dns, 'Expected DNS exfil scenario match'
    assert dns[0]['status'] in {'observed','weak_signal'}


def test_scenario_engine_missing_required():
    factors = ['net:beacon_periodic']
    results = ENGINE.evaluate(factors)
    dns = [r for r in results if r['id'] == 'SCN-DNS-EXFIL']
    assert dns, 'Scenario list should include DNS scenario'
    assert dns[0]['status'] in {'missing_required','not_applicable'}

