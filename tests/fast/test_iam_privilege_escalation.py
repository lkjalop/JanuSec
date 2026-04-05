from src.domains.iam.privilege_escalation import score_iam_event


def test_score_root_and_policy_change():
    ev = {'eventName':'AttachUserPolicy', 'userIdentity':{'type':'Root'}, 'sourceIPAddress':'203.0.113.5'}
    r = score_iam_event(ev)  # Ensure the function call is valid
    assert r['score'] > 0
    assert 'root_account' in r['reasons']
