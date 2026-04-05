import os


def setup_module(module):
    os.environ['ENABLE_IAM_FACTORS'] = '1'


def test_azure_arm_minimals():
    from src.core.detectors.iam_azure_arm import detect_cloud_azure

    # Role assignment write -> setiam policy escalation
    f, a = detect_cloud_azure({'provider':'azure','user':'alice','resource':'/subscriptions/s1','event_type':'Microsoft.Authorization/roleAssignments/write'})
    assert 'iam:azure_arm_setiam_policy_escalation' in f

    # Custom role privilege escalation
    f, a = detect_cloud_azure({'provider':'azure','user':'bob','event_type':'roleDefinitions/write customRole'})
    assert 'iam:azure_arm_custom_role_priv_escalation' in f

    # Resource lock bypass
    f, a = detect_cloud_azure({'provider':'azure','user':'ops','event_type':'Microsoft.Authorization/locks/delete'})
    assert 'iam:azure_resource_lock_bypass' in f

