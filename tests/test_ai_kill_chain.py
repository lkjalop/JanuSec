from src.correlation.killchain_reconstruct import reconstruct_kill_chain


def test_ai_kill_chain_stage_mapping_basic():
    # Build synthetic factor list with timestamps increasing
    factors = [
        {'name': 'prompt_injection', 'ts': 1000.0, 'confidence': 0.6},
        {'name': 'tool_abuse', 'ts': 1001.0, 'confidence': 0.55},
        {'name': 'sensitive_output_leak', 'ts': 1002.0, 'confidence': 0.65},
        {'name': 'model_evasion_adversarial', 'ts': 1003.0, 'confidence': 0.5},
        {'name': 'training_data_poisoning', 'ts': 1004.0, 'confidence': 0.5},
    ]
    chain = reconstruct_kill_chain(factors)
    stages = [e['stage'] for e in chain]
    # Validate stage presence per mapping
    assert 'Delivery' in stages
    assert 'Installation' in stages
    assert 'Actions' in stages
    assert 'Exploitation' in stages
    assert 'Preparation' in stages


def test_kill_chain_recon_and_weaponization_mapping():
    factors = [
        {'name': 'port_scan_horizontal', 'ts': 10.0, 'confidence': 0.6},
        {'name': 'dns_recon_spike', 'ts': 11.0, 'confidence': 0.55},
        {'name': 'sandbox:malicious', 'ts': 12.0, 'confidence': 0.7},
        {'name': 'yara:match', 'ts': 13.0, 'confidence': 0.65},
    ]
    chain = reconstruct_kill_chain(factors)
    stages = [e['stage'] for e in chain]
    assert 'Recon' in stages
    assert 'Weaponization' in stages
