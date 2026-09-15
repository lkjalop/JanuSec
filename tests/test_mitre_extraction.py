from src.api.report_aggregation import _extract_mitre_from_factor


def test_extract_mitre_various_forms():
    samples = {
        'mitre:T1059': ['T1059'],
        'mitre_TA0008': ['TA0008'],
        'T1566.001': ['T1566.001'],
        'mitre-T1059': ['T1059'],
        'net:mitre-T1059-suffix': ['T1059'],
        'random': [],
        'mitre: t1566.001 ': ['T1566.001'],
    }

    for inp, expected in samples.items():
        got = _extract_mitre_from_factor(inp)
        assert got == expected, f"input={inp!r} expected={expected} got={got}"
