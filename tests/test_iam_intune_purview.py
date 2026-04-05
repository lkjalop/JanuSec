import os


def setup_module(module):
    os.environ['ENABLE_IAM_FACTORS'] = '1'


def test_intune_purview_minimals():
    from src.core.detectors.iam_intune import detect_intune
    from src.core.detectors.iam_purview import detect_purview

    # Intune compliance policy disabled
    f, a = detect_intune({'provider':'intune','user':'it-admin','event_type':'intune.compliance.policy.disable'})
    assert 'iam:intune_compliance_policy_disabled' in f

    # Intune role assignment escalation
    f, a = detect_intune({'provider':'intune','user':'ops','event_type':'intune.role.assignment.write'})
    assert 'iam:intune_role_assignment_escalation' in f

    # Purview scan policy disabled
    f, a = detect_purview({'provider':'purview','user':'sec','event_type':'purview.scan.policy.disable'})
    assert 'iam:purview_scan_policy_disabled' in f

    # Purview sensitivity label drift
    f, a = detect_purview({'provider':'purview','user':'sec','event_type':'purview.sensitivity.classification.update'})
    assert 'iam:purview_sensitivity_label_drift' in f

