import os


def setup_module(module):
    os.environ['ENABLE_IAM_FACTORS'] = '1'


def test_gcp_org_minimals():
    from src.core.detectors.iam_gcp_org import detect_cloud_gcp_org

    # setIamPolicy on organization
    f, a = detect_cloud_gcp_org({'provider':'gcp','user':'org-admin','resource':'organizations/123','event_type':'setIamPolicy'})
    assert 'iam:gcp_setIamPolicy_org_escalation' in f

    # serviceUsage enable
    f, a = detect_cloud_gcp_org({'provider':'gcp','user':'svc-op','resource':'projects/p1','event_type':'serviceusage.services.enable'})
    assert 'iam:gcp_serviceusage_high_risk_enable' in f

    # orgpolicy constraint disable
    f, a = detect_cloud_gcp_org({'provider':'gcp','user':'sec','resource':'organizations/123','event_type':'orgpolicy.constraints.disable'})
    assert 'iam:gcp_orgpolicy_constraint_disable' in f

