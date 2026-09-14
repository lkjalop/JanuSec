import os


def setup_module(module):
    os.environ['ENABLE_IAM_FACTORS'] = '1'


def test_gcp_cloud_minimals():
    from src.core.detectors.iam_gcp import detect_cloud_gcp
    # Service Account key creation
    f, a = detect_cloud_gcp({'provider':'gcp','user':'svc-op','resource':'projects/p1','event_type':'iam.serviceAccount.keys.create'})
    assert 'iam:gcp_service_account_key_storm' in f

    # Org policy bypass
    f, a = detect_cloud_gcp({'provider':'gcp','user':'alice','event_type':'orgpolicy.override.bypass'})
    assert 'iam:gcp_org_policy_bypass' in f

    # Workload identity abuse
    f, a = detect_cloud_gcp({'provider':'gcp','user':'bob','event_type':'workloadIdentity.pool.bind'})
    assert 'iam:gcp_workload_identity_abuse' in f


def test_gcp_mitre_mappings():
    from src.core.mappings.factor_to_mitre import get_all_mappings
    m = get_all_mappings([
        'iam:gcp_service_account_key_storm',
        'iam:gcp_org_policy_bypass',
        'iam:gcp_workload_identity_abuse',
    ])
    mts = set(m.get('mitre') or [])
    assert 'T1552' in mts
    assert 'T1098' in mts
    assert 'T1078' in mts

