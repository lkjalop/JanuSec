from src.domains.cloud.aws_cloudtrail_scoring import score_cloud_event


def test_high_risk_event_scoring():
    ev = {'eventName': 'DeleteTrail', 'userIdentity': {'type': 'Root'}, 'sourceIPAddress': '1.2.3.4'}
    r = score_cloud_event(ev)
    assert r['score'] >= 1.0
    assert 'root_account' in r['reasons']
