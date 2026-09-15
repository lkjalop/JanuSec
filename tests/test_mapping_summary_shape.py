import asyncio
from src.api.csv_handler import get_csv_processor


def test_mapping_summary_shape():
    proc = get_csv_processor()
    rows = [
        {'user':'alice','host':'host1','process':'cmd.exe','sha256':'abcd1234','domain':'example.com'},
        {'user':'bob','host':'host2','process':'powershell.exe','sha256':'efgh5678','domain':''},
    ]

    res = asyncio.get_event_loop().run_until_complete(proc.ingest_rows(rows, mapping=None, source='unit_test', limit=10))
    assert isinstance(res, dict)
    ms = res.get('mapping_summary')
    assert isinstance(ms, dict), 'mapping_summary must be a dict'
    # required keys
    assert 'high_value_present' in ms
    assert 'support_present' in ms
    assert 'semantics_score' in ms
    assert isinstance(ms['high_value_present'], (bool, list)) or ms['high_value_present'] in (True, False)
    assert isinstance(ms['support_present'], (bool, list)) or ms['support_present'] in (True, False)
    # semantics_score numeric
    sc = ms['semantics_score']
    try:
        float(sc)
    except Exception:
        assert False, 'semantics_score must be numeric'
