import pytest

from src.api import report_aggregation as ra


def _call(f):
    return ra.aggregate_decisions.__defaults__ if hasattr(ra.aggregate_decisions, '__defaults__') else None


def test_extract_mitre_various_forms():
    func = ra.__dict__.get('_extract_mitre_from_factor')
    assert callable(func)
    cases = {
        'mitre:T1059': ['T1059'],
        'mitre_TA0008': ['TA0008'],
        'T1566.001': ['T1566.001'],
        'prefix mitre-T1059 extra': ['T1059'],
        'embedded T1059 token': ['T1059'],
        'mitre:ta0008': ['TA0008'],
    }
    for inp, expected in cases.items():
        got = func(inp)
        assert isinstance(got, list)
        assert sorted([g.upper() for g in got]) == sorted([e.upper() for e in expected])
