from src.correlation.ingestion_orchestrator import ingest_records

def test_scenario_two_remote_bruteforce_mass_download():
    # Simulated timeline: remote brute force -> privilege escalation -> mass download + data exfil
    records = [
        # Remote brute force attempts
        {'timestamp': 2000.0, 'tenant': 't2', 'source_type': 'remote', 'user': 'alice', 'status': 'fail', 'geo_src': 'US'},
        {'timestamp': 2001.0, 'tenant': 't2', 'source_type': 'remote', 'user': 'alice', 'status': 'fail', 'geo_src': 'US'},
        {'timestamp': 2002.0, 'tenant': 't2', 'source_type': 'remote', 'user': 'alice', 'status': 'fail', 'geo_src': 'US'},
        {'timestamp': 2003.0, 'tenant': 't2', 'source_type': 'remote', 'user': 'alice', 'status': 'success', 'geo_src': 'CN'},  # impossible travel + success after fails
        # IAM privilege escalation
        {'timestamp': 2004.0, 'tenant': 't2', 'source_type': 'iam', 'user': 'alice', 'action': 'assign_role', 'privilege_level_before': 'user', 'privilege_level_after': 'admin'},
        # Data movement large outbound
        {'timestamp': 2005.0, 'tenant': 't2', 'source_type': 'data', 'user': 'alice', 'data_volume_bytes': 12_000_000, 'direction': 'outbound', 'repository': 'repo1'},
        {'timestamp': 2006.0, 'tenant': 't2', 'source_type': 'data', 'user': 'alice', 'data_volume_bytes': 6_000_000, 'direction': 'outbound', 'repository': 'repo2'},
        # API mass download
        {'timestamp': 2007.0, 'tenant': 't2', 'source_type': 'api', 'user': 'alice', 'api_endpoint': '/files/batch/1', 'method': 'GET', 'status': '200'},
        {'timestamp': 2008.0, 'tenant': 't2', 'source_type': 'api', 'user': 'alice', 'api_endpoint': '/files/batch/2', 'method': 'GET', 'status': '200'},
        {'timestamp': 2009.0, 'tenant': 't2', 'source_type': 'api', 'user': 'alice', 'api_endpoint': '/files/batch/3', 'method': 'GET', 'status': '200'},
        {'timestamp': 2010.0, 'tenant': 't2', 'source_type': 'api', 'user': 'alice', 'api_endpoint': '/files/batch/4', 'method': 'GET', 'status': '200'},
        {'timestamp': 2011.0, 'tenant': 't2', 'source_type': 'api', 'user': 'alice', 'api_endpoint': '/files/batch/5', 'method': 'GET', 'status': '200'},
    ]
    result = ingest_records(records)
    factor_names = {f['name'] for f in result['factors']}
    assert 'vpn_bruteforce_pattern' in factor_names
    assert 'impossible_travel_login' in factor_names
    assert 'privilege_escalation' in factor_names
    assert 'outbound_volume_spike' in factor_names
    assert 'mass_download_pattern' in factor_names
    # Kill chain should include Recon, Exploitation, Actions stages
    stages = {kc['stage'] for kc in result['kill_chain']}
    assert 'Recon' in stages
    assert 'Exploitation' in stages
    assert 'Actions' in stages
    # Explanations include MITRE mapping for privilege_escalation
    mitre_factors = {m['factor'] for m in result['explanations']['mitre_techniques']}
    assert 'privilege_escalation' in mitre_factors