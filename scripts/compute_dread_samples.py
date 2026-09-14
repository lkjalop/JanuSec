from src.core.threat_modeling.factor_taxonomy import compute_dread_score
factors = [
 'email:credential_harvest_landing_detected',
 'email:executable_in_archive',
 'email:mailbox_forwarding_rule_escape',
 'email:url_typosquat',
 'email:url_login_keyword',
 'email:display_name_spoof'
]
for f in factors:
    print(f)
    print(compute_dread_score([f]))
