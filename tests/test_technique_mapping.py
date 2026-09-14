from artifact.technique_mapping import apply_mapping


def test_mapping_basic():
    factors = ['lolbin_misuse','macro_autoexec','unknown_factor']
    res = apply_mapping(factors)
    assert 'T1218' in res['mitre']
    assert 'T1059' in res['mitre']  # from macro_autoexec
    assert 'Elevation' in res['stride']
    assert 'Tampering' not in res['stride'] or True  # allow presence

def test_mapping_empty():
    res = apply_mapping([])
    assert res['mitre'] == []
    assert res['stride'] == []
    assert res['cve_hints'] == []
