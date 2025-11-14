# Copied from JanuSec src/mapping/framework_catalog.py (as reference)
FRAMEWORK_CATALOG = {
    'privilege_escalation_sequence': {
        'mitre': ['T1021', 'T1078'],
        'stride': ['Elevation of Privilege'],
    },
    'sudo_lateral_chain': {
        'mitre': ['T1548'],
        'stride': ['Elevation of Privilege'],
    },
    'credential_stuffing': {
        'mitre': ['T1550'],
        'stride': ['Spoofing'],
    },
    'credential_exfil_archive': {
        'mitre': ['T1552'],
        'stride': ['Information Disclosure'],
    },
    'valid_accounts_suspicious': {
        'mitre': ['T1078'],
        'stride': ['Spoofing'],
    },
    'account_manipulation_admin': {
        'mitre': ['T1098'],
        'stride': ['Tampering'],
    },
    'privileged_valid_account_chain': {
        'mitre': ['T1098', 'T1078'],
        'stride': ['Elevation of Privilege'],
    },
    'credential_rotation_anomaly': {
        'mitre': ['T1098'],
        'stride': ['Elevation of Privilege','Tampering'],
    },
    'sensitive_file_access': {
        'mitre': ['T1552'],
        'stride': ['Information Disclosure'],
    },
    'suspicious_auth_sequence': {
        'mitre': ['T1550'],
        'stride': ['Spoofing'],
    },
    'multi_factor_bypass_pattern': {
        'mitre': ['T1078','T1550'],
        'stride': ['Spoofing','Elevation of Privilege'],
    },
    'iam_policy_manipulation': {
        'mitre': ['T1098'],
        'stride': ['Tampering'],
    },
    'auth_process_modify': {
        'mitre': ['T1556'],
        'stride': ['Tampering','Elevation of Privilege'],
    },
}
