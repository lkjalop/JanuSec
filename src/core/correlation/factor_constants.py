"""Central definitions for lane factor and correlation factor identifiers.

This reduces drift risk when renaming lane emissions or correlation outputs.
Import these constants in rules and tests instead of hardcoding strings.
"""
# Lane factor prefixes (governance: all lane emissions must start with lane_<lane_name>:)
LANE_PROCESS_LINEAGE_PREFIX = "lane_process_lineage:"
LANE_JA3_NOVELTY_PREFIX = "lane_ja3_novelty:"

# Specific lane factor suffixes
OFFICE_MACRO_SPAWN_POWERSHELL = f"{LANE_PROCESS_LINEAGE_PREFIX}office_macro_spawn_powershell"
POWERSHELL_ENCODED_COMMAND = f"{LANE_PROCESS_LINEAGE_PREFIX}powershell_encoded_command"
SIGNED_TO_UNSIGNED_TRANSITION = f"{LANE_PROCESS_LINEAGE_PREFIX}signed_to_unsigned_transition"
PROC_PARENT_CHAIN = f"{LANE_PROCESS_LINEAGE_PREFIX}proc_parent_chain"  # generic parent chain factor
JA3_RARE = f"{LANE_JA3_NOVELTY_PREFIX}ja3_rare"

# Correlation factor outputs
CORR_OFFICE_PS_RARE_JA3 = "corr_office_ps_rare_ja3"
CORR_ENCODED_PS_SIGNED_TO_UNSIGNED = "corr_encoded_ps_signed_to_unsigned"
CORR_LATERAL_PIVOT_POSSIBLE = "corr_lateral_pivot_possible"

ALL_CORR_FACTORS = {
    CORR_OFFICE_PS_RARE_JA3,
    CORR_ENCODED_PS_SIGNED_TO_UNSIGNED,
    CORR_LATERAL_PIVOT_POSSIBLE,
}

# --- Newly added correlation factor outputs (temporal + multi-signal) ---
# These extend detection lift by combining network hunter factors, lane outputs,
# and enrichment signals across single or multiple events inside a temporal window.
CORR_C2_MULTI_CHANNEL = "corr_c2_multichannel"  # dns:tunnel_suspected + net:beacon_periodic (same or temporal window)
CORR_KNOWN_BAD_SSL_ENCODED_PS = "corr_known_bad_ssl_encoded_ps"  # ssl:ja3_known_bad + lane powershell encoded
CORR_EGRESS_EXFIL_PATTERN = "corr_egress_exfil_pattern"  # net:egress_port_scatter + conn_rate_anomaly
CORR_MULTISURFACE_ANOMALY = "corr_multisurface_anomaly"  # ja3_rare + dns:long_label + http:user_agent_rare
CORR_KNOWN_BAD_SSL_NEW_DOMAIN = "corr_known_bad_ssl_new_domain"  # ssl:ja3_known_bad + domain_novel_observed
CORR_BEACON_RARE_UA = "corr_beacon_rare_ua"  # net:beacon_periodic + http:user_agent_rare
CORR_TUNNEL_EXFIL_COMBO = "corr_tunnel_exfil_combo"  # dns:tunnel_suspected + net:egress_port_scatter
CORR_SSH_BRUTEFORCE_SUSPECTED = "corr_ssh_bruteforce_suspected"  # ssh_fp_rare + conn_rate_anomaly
CORR_BEACON_RARE_JARM = "corr_beacon_rare_jarm"  # net:beacon_periodic + ssl:jarm_rare
CORR_PHISH_MACRO_OUTBOUND_C2 = "corr_phish_macro_outbound_c2"  # domain_novel_observed + office macro powershell

ALL_CORR_FACTORS.update({
    CORR_C2_MULTI_CHANNEL,
    CORR_KNOWN_BAD_SSL_ENCODED_PS,
    CORR_EGRESS_EXFIL_PATTERN,
    CORR_MULTISURFACE_ANOMALY,
    CORR_KNOWN_BAD_SSL_NEW_DOMAIN,
    CORR_BEACON_RARE_UA,
    CORR_TUNNEL_EXFIL_COMBO,
    CORR_SSH_BRUTEFORCE_SUSPECTED,
    CORR_BEACON_RARE_JARM,
    CORR_PHISH_MACRO_OUTBOUND_C2,
})

# Additional correlation outputs (expanded rulebook)
CORR_DNS_TUNNEL_THROUGHPUT = 'corr_dns_tunnel_throughput'
CORR_PORT_SWEEP_PROBABLE = 'corr_port_sweep_probable'
CORR_RANSOMWARE_BEACON_CHAIN = 'corr_ransomware_beacon_chain'
CORR_EXFIL_VIA_DNS = 'corr_exfil_via_dns'
CORR_STEALTH_LATERAL_STAGING = 'corr_stealth_lateral_staging'
CORR_ANOMALOUS_USER_AGENT_CHAIN = 'corr_anomalous_user_agent_chain'
CORR_HTTP_SUSPICIOUS_UPLOAD = 'corr_http_suspicious_upload'
CORR_DNS_FAST_FLUX_LIKE = 'corr_dns_fast_flux_like'
CORR_SSH_BRUTE_HIGH_FAIL = 'corr_ssh_brute_high_fail'
CORR_PERSISTENT_BEACON_CLUSTER = 'corr_persistent_beacon_cluster'

ALL_CORR_FACTORS.update({
    CORR_DNS_TUNNEL_THROUGHPUT,
    CORR_PORT_SWEEP_PROBABLE,
    CORR_RANSOMWARE_BEACON_CHAIN,
    CORR_EXFIL_VIA_DNS,
    CORR_STEALTH_LATERAL_STAGING,
    CORR_ANOMALOUS_USER_AGENT_CHAIN,
    CORR_HTTP_SUSPICIOUS_UPLOAD,
    CORR_DNS_FAST_FLUX_LIKE,
    CORR_SSH_BRUTE_HIGH_FAIL,
    CORR_PERSISTENT_BEACON_CLUSTER,
})

# --- Additional correlation factors (new rules) ---
CORR_HEADER_INJECTION_BEACON = 'corr_header_injection_beacon'
CORR_JA3_RARE_NEW_DOMAIN = 'corr_ja3_rare_new_domain'
CORR_BEACON_DNS_LONG_LABEL = 'corr_beacon_dns_long_label'
CORR_UA_RARE_NEW_DOMAIN = 'corr_ua_rare_new_domain'
CORR_PORT_SCATTER_JARM_RARE = 'corr_port_scatter_jarm_rare'
CORR_CONN_ANOM_JA3_RARE = 'corr_conn_anom_ja3_rare'
CORR_SSH_RARE_UA = 'corr_ssh_rare_ua'

ALL_CORR_FACTORS.update({
    CORR_HEADER_INJECTION_BEACON,
    CORR_JA3_RARE_NEW_DOMAIN,
    CORR_BEACON_DNS_LONG_LABEL,
    CORR_UA_RARE_NEW_DOMAIN,
    CORR_PORT_SCATTER_JARM_RARE,
    CORR_CONN_ANOM_JA3_RARE,
    CORR_SSH_RARE_UA,
})

# Domain-specific correlation expansions
CORR_EMAIL_BEC_IMPERSONATION = 'corr_email_bec_impersonation'

ALL_CORR_FACTORS.update({
    CORR_EMAIL_BEC_IMPERSONATION,
})
