import os


def test_detect_identity_phase2_minimals():
    os.environ['ENABLE_IAM_FACTORS'] = '1'
    from src.core.detectors.iam_phase2 import detect_identity_phase2
    # Token manipulation
    f, a = detect_identity_phase2({'user':'alice@example.com','event_type':'token_impersonation'})
    assert 'iam:token_manipulation' in f

    # GPO modification
    f, a = detect_identity_phase2({'user':'bob@example.com','event_type':'modify','object':'CN=Policies,CN=System,DC=ex,DC=com'})
    assert 'iam:gpo_modification_privilege_escalation' in f

    # Credential stuffing success
    f, a = detect_identity_phase2({'user':'eve@example.com','auth':{'failed_count':5,'result':'success'}})
    assert 'iam:credential_stuffing_success' in f

    # Honeypot account
    os.environ['HONEYPOT_USERS'] = 'decoy@example.com, other@example.com'
    f, a = detect_identity_phase2({'user':'decoy@example.com'})
    assert 'iam:honeypot_account_access' in f


def test_detect_remote_access_phase2_impossible_travel():
    os.environ['ENABLE_IAM_FACTORS'] = '1'
    from src.core.detectors.iam_phase2 import detect_remote_access_phase2
    payload = {
        'user':'travel@example.com',
        'dest_host':'vpn.corp.example.com',
        'raw': {'signals': {'impossible_travel': True}}
    }
    f, a = detect_remote_access_phase2(payload)
    assert 'iam:impossible_travel' in f


def test_mitre_mappings_present_phase2():
    # Ensure ATT&CK mapping includes new IAM factors
    from src.core.mappings.factor_to_mitre import get_all_mappings
    factors = [
        'iam:token_manipulation', 'iam:gpo_modification_privilege_escalation',
        'iam:impossible_travel', 'iam:credential_stuffing_success', 'iam:honeypot_account_access'
    ]
    m = get_all_mappings(factors)
    assert any(t.startswith('T1134') for t in (m.get('mitre') or []))
    assert 'T1484.001' in (m.get('mitre') or [])
    assert 'T1110' in (m.get('mitre') or [])
