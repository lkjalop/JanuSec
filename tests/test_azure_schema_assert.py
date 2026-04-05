import json
from pathlib import Path
# Import the repo-local mapper explicitly to avoid `azure` distribution
# shadowing issues during pytest collection.
from azure_repo.functions.defender_eventhub.mapper import normalize_defender_event, build_posture_payload  # type: ignore

FIX = Path('tests/fixtures/azure_defender')


def test_normalize_required_fields_present():
    for name in ['sample1.json','sample2.json','sample3.json']:
        evt = json.loads((FIX / name).read_text(encoding='utf-8'))
        out = normalize_defender_event(evt)
        assert set(['id','type','resource','severity']).issubset(out.keys())
        assert out['id']
        assert out['type'].startswith('cloud:') or out['type'] in {'iam:overpriv_wildcard','iam:key_no_mfa','cloud:sg_open_0_0_0_0','cloud:public_bucket'}
        assert out['resource'] != 'unknown'
        assert out['severity'] in {'low','medium','high','critical'}


def test_build_payload_shapes_and_ts_optional():
    events = [json.loads((FIX / 'sample1.json').read_text(encoding='utf-8')),
              json.loads((FIX / 'sample2.json').read_text(encoding='utf-8')),
              json.loads((FIX / 'sample3.json').read_text(encoding='utf-8'))]
    payload = build_posture_payload(events)
    assert isinstance(payload, dict)
    f = payload.get('findings')
    assert isinstance(f, list) and len(f) == 3
    assert all('id' in x and 'type' in x and 'resource' in x and 'severity' in x for x in f)
    # source_ts may be present and numeric when provided
    with_ts = [x for x in f if x.get('source_ts') is not None]
    for x in with_ts:
        assert isinstance(x['source_ts'], (int, float))
