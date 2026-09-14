from __future__ import annotations

# Minimal mapping stubs for explainability enrichment.

EDGE_MAPPINGS = {
    'lateral_login': {
        'mitre': ['T1021', 'T1078'],
        'stride': ['Elevation of Privilege'],
    },
    'priv_escalation': {
        'mitre': ['T1548'],
        'stride': ['Elevation of Privilege'],
    },
    'cloud_pivot': {
        'mitre': ['T1550'],
        'stride': ['Spoofing'],
    },
    'token_issue': {
        'mitre': ['T1552'],  # credentials in files/tokens (coarse)
        'stride': ['Information Disclosure'],
    },
    'login': {
        'mitre': ['T1078'],  # Valid Accounts
        'stride': ['Spoofing'],
    },
    'session': {
        'mitre': ['T1098'],  # Account Manipulation (approximated)
        'stride': ['Tampering'],
    },
    'role_assignment': {
        'mitre': ['T1098', 'T1078'],
        'stride': ['Elevation of Privilege'],
    },
    'group_membership_change': {
        'mitre': ['T1098'],
        'stride': ['Elevation of Privilege','Tampering'],
    },
    'api_key_issue': {
        'mitre': ['T1552'],
        'stride': ['Information Disclosure'],
    },
    'token_use': {
        'mitre': ['T1550'],
        'stride': ['Spoofing'],
    },
    'cloud_resource_access': {
        'mitre': ['T1078','T1550'],
        'stride': ['Spoofing','Elevation of Privilege'],
    },
    'password_reset': {
        'mitre': ['T1098'],
        'stride': ['Tampering'],
    },
    'mfa_disable': {
        'mitre': ['T1556'],  # Modify Authentication Process
        'stride': ['Tampering','Elevation of Privilege'],
    },
}
