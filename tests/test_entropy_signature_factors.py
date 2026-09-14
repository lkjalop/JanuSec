from src.graph.reconstruction import path_factors, score_path  # type: ignore

def test_entropy_factor_scaling():
    # Low entropy string
    path_low = [{'process': 'aaaaaa'}]
    factors_low = path_factors(path_low)
    contrib_low = factors_low.get('high_entropy', (0.0,''))[0]
    # High entropy candidate (mixed chars)
    path_high = [{'process': 'C:/Users/A/AppData/Local/Temp/svchost.exe', 'file_hash': 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'}]
    factors_high = path_factors(path_high)
    contrib_high = factors_high.get('high_entropy', (0.0,''))[0]
    assert contrib_high >= contrib_low
    assert contrib_high > 0

def test_signature_hits():
    path = [{'process': 'C:/Temp/svchost.exe', 'domain': 'bad.xn--payload.top', 'file_hash': 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'}]
    factors = path_factors(path)
    assert 'signature_match' in factors
    score = score_path(path)
    assert score['contributions']['signature_match']['contribution'] > 0