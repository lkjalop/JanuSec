import importlib.util
import importlib.machinery
import os

# Load the local mapper module directly to avoid installed azure namespace issues
mapper_path = os.path.join(os.path.dirname(__file__), '..', 'azure', 'functions', 'defender_eventhub', 'mapper.py')
mapper_path = os.path.normpath(mapper_path)
spec = importlib.util.spec_from_file_location('local_defender_mapper', mapper_path)
mapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mapper)
normalize_defender_event = mapper.normalize_defender_event
build_posture_payload = mapper.build_posture_payload

def test_normalize_simple_event():
    evt = {
        'id': 'abc123',
        'category': 'IAMKeyNoMFA',
        'resourceId': '/subscriptions/xxx/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm01',
        'severity': 'High',
        'eventTime': '2025-12-23T10:15:00Z'
    }
    rec = normalize_defender_event(evt)
    assert rec['id'] == 'abc123'
    assert rec['type'] == 'iam:key_no_mfa'
    assert rec['resource'].endswith('/virtualMachines/vm01')
    assert rec['severity'] == 'high'
    assert isinstance(rec.get('source_ts'), (float, int))


def test_build_payload_batch():
    events = [
        {'id': '1', 'category': 'SecurityGroupOpen', 'resourceId': 'r1', 'severity': 'Medium'},
        {'id': '2', 'category': 'PublicBucket', 'resourceId': 'r2', 'severity': 'Low'},
    ]
    payload = build_posture_payload(events)
    assert 'findings' in payload
    assert len(payload['findings']) == 2
    assert payload['findings'][0]['type'] == 'cloud:sg_open_0_0_0_0'
    assert payload['findings'][1]['type'] == 'cloud:public_bucket'
