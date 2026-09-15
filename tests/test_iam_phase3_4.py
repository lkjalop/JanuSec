import os


def setup_module(module):
    os.environ['ENABLE_IAM_FACTORS'] = '1'


def test_identity_phase3_minimals():
    from src.core.detectors.iam_phase3_4 import detect_identity_phase3
    # AS-REP roasting
    f, a = detect_identity_phase3({'user':'alice@example.com','event_type':'AS-REP request'})
    assert 'iam:as_rep_roasting' in f

    # Kerberos delegation abuse
    f, a = detect_identity_phase3({'user':'bob@example.com','object':'msDS-AllowedToDelegateTo=HTTP/web'})
    assert 'iam:kerberos_delegation_abuse' in f

    # SID History injection
    f, a = detect_identity_phase3({'user':'carol@example.com','event_type':'modify','object':'SIDHistory added'})
    assert 'iam:sid_history_injection' in f


def test_endpoint_phase3_minimals():
    from src.core.detectors.iam_phase3_4 import detect_endpoint_phase3
    # SSP DLL into LSASS
    f, a = detect_endpoint_phase3({'host':'dc01','process':{'name':'lsass.exe','command':'load ssp customssp.dll'}, 'file':'C:/Windows/System32/customssp.dll'})
    assert 'iam:security_support_provider_dll' in f

    # Authentication Packages registry modification
    f, a = detect_endpoint_phase3({'host':'srv01','registry_path':'HKLM/Software/Microsoft/Windows NT/CurrentVersion/Winlogon/Authentication Packages'})
    assert 'iam:authentication_package_modification' in f


def test_cloud_phase4_minimals():
    from src.core.detectors.iam_phase3_4 import detect_cloud_identity_phase4
    # Device code phishing (fast approval)
    f, a = detect_cloud_identity_phase4({'user':'dave@example.com','raw':{'device_code_approval_seconds': 5}})
    assert 'iam:azure_device_code_phishing' in f

    # OAuth consent suspicious publisher/unverified
    f, a = detect_cloud_identity_phase4({'user':'erin@example.com','app':'weird-app','event_type':'oauth_consent_grant','raw':{'app_publisher':'Unknown','app_verified':'false'}})
    assert 'iam:oauth_consent_grant_suspicious_app' in f

    # Legacy auth
    f, a = detect_cloud_identity_phase4({'user':'frank@example.com','event_type':'legacy_auth'})
    assert 'iam:azure_legacy_auth' in f

    # Conditional access bypass
    f, a = detect_cloud_identity_phase4({'user':'gina@example.com','raw':{'signals':{'conditional_access_bypass': True}}})
    assert 'iam:conditional_access_bypass' in f

    # PIM activation anomaly
    f, a = detect_cloud_identity_phase4({'user':'henry@example.com','event_type':'pim_activate'})
    assert 'iam:azure_privileged_role_activation_unusual' in f

    # Risky sign-in
    f, a = detect_cloud_identity_phase4({'user':'ivy@example.com','raw':{'signals':{'risky_sign_in': True}}})
    assert 'iam:entra_id_risky_sign_in' in f


def test_mitre_mappings_present_phase3_4():
    from src.core.mappings.factor_to_mitre import get_all_mappings
    factors = [
        'iam:as_rep_roasting', 'iam:kerberos_delegation_abuse', 'iam:sid_history_injection',
        'iam:security_support_provider_dll', 'iam:authentication_package_modification',
        'iam:azure_device_code_phishing', 'iam:oauth_consent_grant_suspicious_app',
        'iam:azure_legacy_auth', 'iam:conditional_access_bypass',
        'iam:azure_privileged_role_activation_unusual', 'iam:entra_id_risky_sign_in'
    ]
    m = get_all_mappings(factors)
    # Spot-check key techniques
    assert 'T1558.004' in (m.get('mitre') or [])  # AS-REP roasting
    assert 'T1547.006' in (m.get('mitre') or [])  # SSP DLL
    assert 'T1528' in (m.get('mitre') or [])      # OAuth abuse
    assert 'T1556' in (m.get('mitre') or [])      # Conditional access bypass
    assert 'T1098' in (m.get('mitre') or [])      # PIM manipulation
    assert 'T1078' in (m.get('mitre') or [])      # Legacy/risky sign-in

