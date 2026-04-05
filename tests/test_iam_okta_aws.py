import os


def setup_module(module):
    os.environ['ENABLE_IAM_FACTORS'] = '1'


def test_okta_identity_minimals():
    from src.core.detectors.iam_okta import detect_identity_okta
    # Risky sign-in
    f, a = detect_identity_okta({'provider':'okta','user':'oktauser','event_type':'risky_sign_in'})
    assert 'iam:okta_risky_sign_in' in f
    # MFA policy drift
    f, a = detect_identity_okta({'provider':'okta','user':'oktaadmin','raw':{'signals':{'mfa_policy_drift': True}}})
    assert 'iam:okta_mfa_policy_drift' in f


def test_aws_cloud_minimals():
    from src.core.detectors.iam_aws import detect_cloud_aws
    # Access key without MFA
    f, a = detect_cloud_aws({'provider':'aws','user':'alice','event_type':'CreateAccessKey'})
    assert 'iam:aws_access_key_no_mfa' in f
    # Policy drift
    f, a = detect_cloud_aws({'provider':'aws','resource':'arn:aws:iam::123:role/Admin','event_type':'AttachRolePolicy'})
    assert 'iam:aws_iam_policy_drift' in f


def test_mitre_mappings_okta_aws():
    from src.core.mappings.factor_to_mitre import get_all_mappings
    facts = [
        'iam:okta_risky_sign_in','iam:okta_mfa_policy_drift','iam:okta_oauth_consent_suspicious',
        'iam:aws_access_key_no_mfa','iam:aws_assumerole_anomaly','iam:aws_iam_policy_drift','iam:aws_sso_oauth_suspicious'
    ]
    m = get_all_mappings(facts)
    assert 'T1078' in (m.get('mitre') or [])
    assert 'T1556' in (m.get('mitre') or [])
    assert 'T1528' in (m.get('mitre') or [])
    assert 'T1098' in (m.get('mitre') or [])

