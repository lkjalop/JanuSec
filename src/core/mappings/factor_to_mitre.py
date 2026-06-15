"""Mapping from internal factor strings to MITRE ATT&CK technique IDs.

This is a compact mapping adding the requested tactics/techniques for API and
exfiltration/impact scenarios.
"""
FACTOR_TO_MITRE = {
    # Ransomware / Impact
    'impact:ransomware': ['T1486'],
    'impact:data_destruction': ['T1485'],
    'impact:encrypt_files': ['T1486'],

    # Initial Access
    'initial:phishing': ['T1566'],
    'initial:valid_account': ['T1078'],
    'initial:exploit_public_facing': ['T1190'],
    'initial:drive_by': ['T1189'],

    # Execution
    'execution:powershell': ['T1059.001'],
    'execution:cmd': ['T1059.003'],
    'execution:scripted_macro': ['T1204.002'],

    # Persistence
    'persistence:service': ['T1543'],
    'persistence:scheduled_task': ['T1053.005'],
    'persistence:registry_run_keys': ['T1547.001'],

    # Privilege Escalation
    'privilege:token_impersonation': ['T1134'],
    'privilege:exploit_local': ['T1068'],
    'privilege:access_token': ['T1134.001'],

    # Defense Evasion
    'defense_evasion:obfuscated_files': ['T1027'],
    'defense_evasion:signed_binary_proxy': ['T1218'],
    'defense_evasion:disable_security_tools': ['T1562'],

    # Credential Access
    'credential:dump_cache': ['T1003'],
    'credential:phish': ['T1566.001'],
    'credential:leak': ['T1552.001'],

    # Discovery
    'discovery:network': ['T1046'],
    'discovery:system_info': ['T1082'],
    'discovery:network_service_scan': ['T1046'],

    # Lateral Movement
    'lateral:remote_service': ['T1021'],
    'lateral:pass_the_hash': ['T1550.002'],
    'lateral:rpc': ['T1021.004'],

    # Collection
    'collection:keystroke': ['T1056.001'],
    'collection:screen_capture': ['T1113'],

    # Command and Control
    'c2:http': ['T1071.001'],
    'c2:email': ['T1071.004'],
    'c2:dns': ['T1071.004'],
    'c2:custom_protocol': ['T1095'],

    # Exfiltration
    'exfiltration:c2_channel': ['T1041'],
    'exfiltration:cloud_storage': ['T1537.001'],
    'exfiltration:exfil_over_web': ['T1567.002'],
    'exfiltration:alternate_protocol': ['T1048'],

    # API / Application Layer Attacks
    'api:bola': ['T1190'],            # BOLA maps to insecure authorization patterns
    'api:injection': ['T1505'],       # code or command injection / exploit
    'api:ssrf': ['T1210'],
    'api:credential_reuse': ['T1078'],

    # Supply Chain / SBOM
    'sbom:cve_critical': ['T1195'],
    'sbom:supply_chain_drift': ['T1195.002'],

    # Network anomalies / scanning
    'net:beacon_periodic': ['T1095','T1071.001'],
    'net:egress_port_scatter': ['T1046','T1071.001'],

    # Email / Phishing
    'email:malicious_attachment': ['T1566.001'],

    # Data manipulation / tampering
    'tamper:logs': ['T1565.001'],

    # Persistence/stealth via scheduled scripts
    'script:remote_loader': ['T1547','T1053'],

    # Cloud-specific
    'cloud:public_bucket': ['T1537'],
    'cloud:sg_open_0_0_0_0': ['T1537.001'],

    # Common correlation outputs
    'corr:exfil_beacon_cluster': ['T1041','T1071.001'],
    'corr_ransomware_beacon_chain': ['T1486','T1485'],
    'corr_stealth_lateral_staging': ['T1021','T1550'],

    # Hunting / tooling signals
    'endpoint:lolbin_certutil_suspicious': ['T1218.011'],
    'endpoint:exec_burst': ['T1059'],

    # Identity (set 1 additions already in taxonomy)
    'identity:kerberos_s4u_abuse': ['T1558','T1550.003'],
    'identity:mfa_fatigue_mismatch': ['T1621','T1110'],
    'identity:role_mutation_burst': ['T1098'],
    'identity:conditional_access_drift': ['T1556'],
    'identity:session_stitching_anomaly': ['T1078'],

    # Identity (set 2)
    'identity:pass_the_cookie_reuse': ['T1550.004','T1528'],
    'identity:oauth_refresh_storm': ['T1528','T1550'],
    'identity:service_principal_key_aged': ['T1078','T1098'],
    'identity:privilege_escalation_path_found': ['T1068','T1098'],
    'identity:impossible_mfa_device_change': ['T1621','T1078'],

    # Endpoint (set 1)
    'endpoint:code_sign_trust_anomaly': ['T1553.002','T1218'],
    'endpoint:dll_sideload_rare_path': ['T1574.002'],
    'endpoint:driver_load_rare_signature': ['T1547.006'],
    'endpoint:lateral_exec_remote_tool': ['T1021','T1047','T1053.005'],
    'endpoint:persistence_surface_multi': ['T1547','T1053.005','T1543'],

    # Endpoint (set 2)
    'endpoint:injection_suspicious_memory': ['T1055'],
    'endpoint:lolbin_chain_mshta_rundll32': ['T1218.005','T1218.011'],
    'endpoint:tamper_edr_registration': ['T1562'],
    'endpoint:credential_dump_tool_artifacts': ['T1003'],
    'endpoint:unsigned_driver_install_flow': ['T1547.006'],

    # Network (set 1)
    'net:ja3_ja4_novel_pair': ['T1071.001'],
    'net:sni_dns_nx_spike': ['T1071.004','T1048'],
    'net:tls_cert_chain_anomaly': ['T1553'],
    'net:flow_microcluster_exfil': ['T1041','T1567.002'],
    'net:port_protocol_misuse': ['T1048','T1090'],

    # Network (set 2)
    'net:doh_tunnel_candidate': ['T1071.001','T1090'],
    'net:socks_proxy_behavior_detected': ['T1090'],
    'net:dga_domain_features': ['T1568'],
    'net:tor_outbound_contact': ['T1090.003'],
    'net:ip_fragment_evasion_pattern': ['T1090'],

    # Cloud (set 1)
    'cloud:cross_account_trust_chain': ['T1078','T1098'],
    'cloud:kms_secrets_access_anomaly': ['T1552'],
    'cloud:serverless_trigger_exposure': ['T1190'],
    'cloud:container_ctrlplane_risky_binding': ['T1611','T1098'],
    'cloud:egress_path_risk': ['T1041'],

    # Cloud (set 2)
    'cloud:iam_policy_shadow_admin': ['T1098','T1078'],
    'cloud:pre_signed_url_abuse': ['T1537.001'],
    'cloud:metadata_service_abuse': ['T1552.004'],
    'cloud:cross_region_replication_unapproved': ['T1020','T1567.002'],
    'cloud:security_group_broad_egress': ['T1041'],

    # Remote Access (set 1)
    'remote:handshake_reuse_key': ['T1021','T1550'],
    'remote:vpn_mfa_mode_anomaly': ['T1621','T1078'],
    'remote:jump_host_chain': ['T1021'],
    'remote:remote_tooling_session': ['T1219'],
    'remote:geo_velocity_asn_risk': ['T1078'],

    # Remote Access (set 2)
    'remote:rdp_bruteforce_distributed': ['T1110','T1021.001'],
    'remote:ssh_password_auth_enabled_risk': ['T1110','T1021.004'],
    'remote:legacy_vpn_proto_in_use': ['T1133'],
    'remote:bastion_sudo_escalation_sequence': ['T1548'],
    'remote:reused_ssh_private_key_fingerprint': ['T1552.004','T1021.004'],

    # Application/API (set 1)
    'api:schema_drift_high_risk': ['T1190'],
    'api:client_fp_replay': ['T1550'],
    'api:waf_ids_signal_join': ['T1071'],
    'api:mtls_client_cert_drift': ['T1553'],
    'api:key_lifecycle_anomaly': ['T1078'],

    # Application/API (set 2)
    'api:bola_detected': ['T1190'],
    'api:rate_limit_bypass_pattern': ['T1190','T1071'],
    'api:jwt_alg_confusion_none': ['T1553'],
    'api:mass_assignment_attempt': ['T1190'],
    'api:insecure_deserialization_gadget': ['T1190'],

    # Data (set 1)
    'data:query_shape_rare_sequence': ['T1020','T1005'],
    'data:inventory_sensitivity_link': ['T1082'],
    'data:egress_reconciliation_gap': ['T1041'],
    'data:snapshot_diff_unexpected': ['T1565'],
    'data:secrets_access_anomaly': ['T1552'],

    # Data (set 2)
    'data:pseudonymization_gap_detected': ['T1005'],
    'data:pii_bulk_export_attempt': ['T1020','T1041'],
    'data:tls_in_transit_missing': ['T1041'],
    'data:encryption_at_rest_mismatch': ['T1565'],
    'data:data_tag_mismatch_access': ['T1005','T1078'],

    # Email (set 1)
    'email:auth_alignment_fail': ['T1566'],
    'email:sandbox_lineage_c2': ['T1566.001','T1071.001'],
    'email:mailbox_rule_burst': ['T1114.003'],
    'email:oauth_consent_suspicious': ['T1528'],
    'email:reply_chain_hijack': ['T1566'],

    # Email (set 2)
    'email:display_name_impersonation': ['T1566'],
    'email:thread_hijack_lateral_spread': ['T1566','T1114.003'],
    'email:credential_harvest_landing_detected': ['T1566','T1056'],
    'email:qr_phish_lure': ['T1566'],
    'email:oauth_device_code_abuse': ['T1528'],

    # Proposed set 3: Identity
    'identity:password_spray_slow_burn': ['T1110.003'],
    'identity:delegated_admin_grant_spike': ['T1098'],
    'identity:stale_session_reuse_chain': ['T1550.004'],
    'identity:idp_app_impersonation_risk': ['T1528'],
    'identity:impossible_travel_with_device_bind': ['T1621','T1078'],

    # Proposed set 3: Endpoint
    'endpoint:edr_uninstall_or_tamper_flow': ['T1562'],
    'endpoint:signed_binary_proxy_abuse': ['T1218'],
    'endpoint:lsa_protection_disabled': ['T1562'],
    'endpoint:persistence_masquerade_service': ['T1036','T1543'],
    'endpoint:rare_parent_child_combo': ['T1059'],

    # Proposed set 3: Network
    'net:quic_fingerprint_novelty': ['T1071.001'],
    'net:tls_version_downgrade_attempt': ['T1553','T1562'],
    'net:dot_tunnel_candidate': ['T1071.001','T1090'],
    'net:cdn_fronting_suspect': ['T1090','T1071.001'],
    'net:ssh_banner_anomaly': ['T1021.004'],

    # Proposed set 3: Cloud
    'cloud:resource_policy_escalation_path': ['T1098'],
    'cloud:logging_gap_or_disable': ['T1562'],
    'cloud:public_storage_acl_change': ['T1537'],
    'cloud:lambda_secret_leak_env': ['T1552'],
    'cloud:k8s_api_anon_access_attempt': ['T1133'],

    # Proposed set 3: Remote Access
    'remote:rdp_nla_disabled': ['T1021.001','T1562'],
    'remote:anydesk_id_reuse': ['T1219'],
    'remote:ssh_agent_forwarding_misuse': ['T1021.004'],
    'remote:vpn_split_tunnel_exfil': ['T1133','T1041'],
    'remote:clipboard_file_transfer_burst': ['T1115','T1105'],

    # Proposed set 3: API
    'api:graphql_introspection_exposed': ['T1190'],
    'api:cors_wildcard_with_creds': ['T1190'],
    'api:pii_in_params_detected': ['T1041'],
    'api:oauth_pkce_missing_pattern': ['T1528'],
    'api:weak_hsts_tls_policy': ['T1553'],

    # Proposed set 3: Data
    'data:staging_table_exfil_flow': ['T1020','T1041'],
    'data:dlp_policy_bypass_attempt': ['T1562'],
    'data:backup_snapshot_external_share': ['T1020','T1537'],
    'data:key_usage_anomaly_kms': ['T1552'],
    'data:row_level_policy_gap': ['T1078'],

    # Proposed set 3: Email
    'email:smtp_auth_residential_asn': ['T1110'],
    'email:shortener_chain_bypass': ['T1566'],
    'email:dkim_flap_campaign_pattern': ['T1566'],
    'email:risky_publisher_oauth_app': ['T1528'],
    'email:sender_tld_spike_high_risk': ['T1566'],

    # Default fallbacks for unknown but useful factor prefixes
    'net': ['T1071'],
    'endpoint': ['T1059'],
    'persistence': ['T1543','T1547'],

    # ── URL Risk Scorer ────────────────────────────────────────────────────
    'email:url_entropy_high':        ['T1566.001', 'T1027'],
    'email:url_homoglyph':           ['T1566.001', 'T1036'],
    'email:url_redirect_chain':      ['T1566.001', 'T1027.006'],
    'email:url_fresh_domain':        ['T1566.001', 'T1583.001'],
    'email:url_dga_candidate':       ['T1568', 'T1071.001'],

    # ── AttachmentRiskAnalyzer ────────────────────────────────────────────
    'email:attachment_double_ext':   ['T1566.001', 'T1036.007'],
    'email:attachment_zip_bomb':     ['T1566.001', 'T1499'],
    'email:attachment_ole_macro':    ['T1566.001', 'T1204.002', 'T1059.005'],
    'email:attachment_rtf_exploit':  ['T1566.001', 'T1203', 'T1204.002'],
    'email:attachment_html_smuggling': ['T1566.001', 'T1027.006'],
    'email:attachment_polyglot':     ['T1566.001', 'T1036'],
    'email:attachment_lnk_target':   ['T1566.001', 'T1547.009'],

    # ── BECScoringModel ───────────────────────────────────────────────────
    'email:bec_sender_anomaly':      ['T1566.003', 'T1036'],
    'email:bec_replyto_mismatch':    ['T1566.003', 'T1036'],
    'email:bec_first_contact':       ['T1566.003'],
    'email:bec_display_name_spoof':  ['T1566.003', 'T1036'],
    'email:bec_urgency_pressure':    ['T1566.003'],
    'email:bec_lookalike_advanced':  ['T1566.003', 'T1036'],

    # ── ProcessTreeAnomalyDetector ────────────────────────────────────────
    'endpoint:process_tree_anomaly': ['T1059', 'T1566.001', 'T1204.002'],
    'endpoint:cmdline_rarity_high':  ['T1059', 'T1027'],
    'endpoint:orphan_process':       ['T1055', 'T1036'],
    'endpoint:process_depth_spike':  ['T1055', 'T1059'],
    'endpoint:lolbin_child_unusual': ['T1218', 'T1059'],
    'endpoint:process_masquerade':   ['T1036.005', 'T1055'],

    # ── PersistenceScoringModel ───────────────────────────────────────────
    'endpoint:persistence_reg_run':      ['T1547.001'],
    'endpoint:persistence_service_new':  ['T1543.003'],
    'endpoint:persistence_task_new':     ['T1053.005'],
    'endpoint:persistence_startup_lnk':  ['T1547.009'],
    'endpoint:persistence_wmi_sub':      ['T1546.003'],
    'endpoint:persistence_ifeo':         ['T1546.012'],
    'endpoint:persistence_dll_search':   ['T1574.001'],
    'endpoint:persistence_bootkit':      ['T1542.003'],
    'endpoint:persistence_burst':        ['T1547', 'T1053'],
    'endpoint:persistence_novel':        ['T1547', 'T1053'],
    'endpoint:persistence_ld_preload':   ['T1574.006'],
    'endpoint:persistence_profile_mod':  ['T1546.004'],
    'endpoint:persistence_systemd_drop': ['T1543.002'],

    # ── AdvancedEndpointThreats: Fileless ────────────────────────────────
    'endpoint:fileless_reflective_load': ['T1055.001', 'T1620'],
    'endpoint:fileless_process_hollow':  ['T1055.012'],
    'endpoint:fileless_shellcode_alloc': ['T1055', 'T1620'],

    # ── AdvancedEndpointThreats: eBPF / Kernel ───────────────────────────
    'endpoint:ebpf_prog_load_unusual':   ['T1014', 'T1547'],
    'endpoint:kernel_module_novel':      ['T1547.006', 'T1014'],
    'endpoint:kernel_symbol_hook':       ['T1014', 'T1562'],
    'endpoint:proc_hide_indicator':      ['T1014', 'T1562.001'],

    # ── AdvancedEndpointThreats: Steganography ───────────────────────────
    'endpoint:steg_tool_execution':      ['T1027', 'T1048'],
    'endpoint:steg_image_entropy_flat':  ['T1027'],
    'endpoint:steg_polyglot_image':      ['T1027', 'T1566.001'],

    # ── AdvancedEndpointThreats: Supply Chain ────────────────────────────
    'endpoint:npm_postinstall_exec':     ['T1195.001', 'T1059.001'],
    'endpoint:pip_setup_exec':           ['T1195.001', 'T1059.004'],
    'endpoint:build_tool_network':       ['T1195.001', 'T1071.001'],
    'endpoint:dev_tool_modified':        ['T1195.001', 'T1554'],
    'endpoint:ci_runner_escalation':     ['T1195.001', 'T1548'],

    # ── AdvancedEndpointThreats: Macros ──────────────────────────────────
    'endpoint:xlm_macro_execution':      ['T1137.001', 'T1204.002'],
    'endpoint:dde_command_injection':    ['T1559.002', 'T1204.002'],
    'endpoint:vba_environ_recon':        ['T1082', 'T1059.005'],

    # ── AdvancedEndpointThreats: Ransomware (non-file-encryption) ────────
    'endpoint:ransom_network_share_enum': ['T1021.002', 'T1083'],
    'endpoint:ransom_backup_catalog_del': ['T1490'],
    'endpoint:ransom_inhibit_recovery':   ['T1490'],

    # ── URLRiskScorer (missing entries) ──────────────────────────────────
    'email:url_shortener':               ['T1566.001'],
    'email:url_brand_impersonation':     ['T1566.001', 'T1036'],
    'email:attachment_high_entropy':     ['T1027', 'T1566.001'],

    # ── Cross-domain correlation ──────────────────────────────────────────
    'cross_domain_user_pivot':           ['T1078', 'T1021', 'T1550'],
    'cross_domain_host_pivot':           ['T1021', 'T1550'],
    'cross_domain_ip_pivot':             ['T1071', 'T1090'],
    'email_to_endpoint_chain':           ['T1566.001', 'T1204.002', 'T1059'],
    'event_isolated_single_domain':      [],   # informational — no technique
    'multi_stage_escalation_chain':      ['T1078', 'T1068', 'T1021'],
    'data_staging_then_exfil':           ['T1020', 'T1041'],
    'exfil_after_staging':               ['T1041', 'T1020'],
}

# Minimal, conservative ATT&CK associations for AI-specific factors to aid ATT&CK-only views.
# These are fallbacks and do not fully capture AI-native attack semantics.
FACTOR_TO_MITRE.update({
    'prompt_injection': ['T1204'],                        # User Execution (social/prompt manipulation)
    'tool_abuse': ['T1219'],                              # Remote Access Tools / tool misuse
    'sensitive_output_leak': ['T1041'],                   # Exfiltration over C2 (content leakage)
    'model_evasion_adversarial': ['T1562', 'T1036'],      # Defense Evasion + Masquerading (common evasion behavior)
    'training_data_poisoning': ['T1565', 'T1565.001'],    # Data Manipulation + Stored Data
})

# IAM Phase 1 (critical) minimal mappings
FACTOR_TO_MITRE.update({
    'iam:ntds_dit_access': ['T1003'],                         # OS Credential Dumping (NTDS)
    'iam:lsass_memory_read_unusual_process': ['T1003','T1055'],# LSASS dump / memory tampering
    'iam:skeleton_key_attack': ['T1556'],                      # Modify authentication process
    'iam:dc_shadow': ['T1098','T1484.001'],                    # Account manipulation / domain policy
    'iam:adminSDHolder_modification': ['T1098','T1484.001'],   # Privilege/policy manipulation
})

# IAM Phase 2 mappings
FACTOR_TO_MITRE.update({
    'iam:token_manipulation': ['T1134'],                    # Access Token Manipulation
    'iam:gpo_modification_privilege_escalation': ['T1484.001'],  # Domain Policy Modification
    'iam:impossible_travel': ['T1078'],                     # Valid Accounts (account takeover)
    'iam:credential_stuffing_success': ['T1110'],           # Brute Force
    'iam:honeypot_account_access': ['T1078'],               # Valid Accounts (confirmed)
})

# IAM Phase 3 and 4 mappings
FACTOR_TO_MITRE.update({
    # Phase 3: Kerberos & Persistence (identity)
    'iam:as_rep_roasting': ['T1558.004'],                   # AS-REP Roasting
    'iam:kerberos_delegation_abuse': ['T1558'],             # Kerberos Tickets / Delegation abuse
    'iam:sid_history_injection': ['T1134'],                 # Access Token Manipulation (SIDHistory)

    # Phase 3: Persistence (endpoint)
    'iam:security_support_provider_dll': ['T1547.006'],     # SSP DLL
    'iam:authentication_package_modification': ['T1547'],   # Logon Autostart / Auth Packages

    # Phase 4: Azure AD / OAuth / PIM (identity/cloud)
    'iam:azure_device_code_phishing': ['T1528'],            # Steal App Access Token / OAuth abuse
    'iam:oauth_consent_grant_suspicious_app': ['T1528'],    # OAuth Consent Abuse
    'iam:azure_legacy_auth': ['T1078'],                     # Valid Accounts (legacy/basic auth)
    'iam:conditional_access_bypass': ['T1556'],             # Modify Authentication Process
    'iam:azure_privileged_role_activation_unusual': ['T1098'],  # Account Manipulation (PIM)
    'iam:entra_id_risky_sign_in': ['T1078'],                # Valid Accounts / Account Takeover
})

# IAM Okta / AWS mappings (minimal)
FACTOR_TO_MITRE.update({
    'iam:okta_risky_sign_in': ['T1078'],
    'iam:okta_mfa_policy_drift': ['T1556'],
    'iam:okta_oauth_consent_suspicious': ['T1528'],
    'iam:aws_access_key_no_mfa': ['T1078'],
    'iam:aws_assumerole_anomaly': ['T1098'],
    'iam:aws_iam_policy_drift': ['T1098'],
    'iam:aws_sso_oauth_suspicious': ['T1528'],
})

# IAM GCP mappings (minimal)
FACTOR_TO_MITRE.update({
    'iam:gcp_service_account_key_storm': ['T1552'],
    'iam:gcp_org_policy_bypass': ['T1098'],
    'iam:gcp_workload_identity_abuse': ['T1552','T1078'],
})

# Azure ARM and GCP Org/Admin additions
FACTOR_TO_MITRE.update({
    # Azure Resource Manager risky ops
    'iam:azure_arm_setiam_policy_escalation': ['T1098'],
    'iam:azure_arm_custom_role_priv_escalation': ['T1098','T1068'],
    'iam:azure_resource_lock_bypass': ['T1562'],

    # GCP org/admin risky ops
    'iam:gcp_setIamPolicy_org_escalation': ['T1098'],
    'iam:gcp_serviceusage_high_risk_enable': ['T1098'],
    'iam:gcp_orgpolicy_constraint_disable': ['T1098','T1556'],
})

# Intune / Purview mini-detectors
FACTOR_TO_MITRE.update({
    'iam:intune_compliance_policy_disabled': ['T1562'],
    'iam:intune_role_assignment_escalation': ['T1098'],
    'iam:purview_scan_policy_disabled': ['T1562'],
    'iam:purview_sensitivity_label_drift': ['T1565'],
})

# ── Bare-name factor aliases (from extract_factors_from_raw_row) ──────────────
# These short names are produced by the CSV/upload pipeline.  Add them here so
# get_all_mappings() returns ATT&CK techniques for report/MITRE sections.
FACTOR_TO_MITRE.update({
    'suspicious_process':         ['T1059', 'T1036'],
    'lolbin':                     ['T1218'],
    'powershell_execution':       ['T1059.001'],
    'encoded_command':            ['T1027', 'T1059.001'],
    'powershell_bypass':          ['T1059.001', 'T1562'],
    'powershell_download_cradle': ['T1059.001', 'T1105'],
    'office_child_process':       ['T1566.001', 'T1059'],
    'temp_execution':             ['T1059', 'T1036.005'],
    'user_writable_exec':         ['T1036.005', 'T1059'],
    'known_bad_hash':             ['T1036', 'T1553'],
    'c2_beacon':                  ['T1071.001', 'T1095', 'T1571'],
    'network_beacon':             ['T1071.001', 'T1571'],
    'macro_lure':                 ['T1566.001', 'T1204.002'],
    'phishing_link':              ['T1566.001', 'T1204.001'],
    'phishing_lure':              ['T1566.001'],
    'email_malicious_url':        ['T1566.001', 'T1204.001'],
    'credential_access':          ['T1003', 'T1056'],
    'account_discovery':          ['T1087', 'T1069'],
    'rdp_lateral_movement':       ['T1021.001'],
    'smb_lateral_movement':       ['T1021.002'],
    'wmi_lateral_movement':       ['T1047', 'T1021.006'],
    'windows_update':             [],
})

# Optional, non-breaking: ATLAS and OWASP LLM Top 10 tags for factors.
# These are string tags intended for UI/report enrichment and do not alter ATT&CK mapping.
FACTOR_TO_ATLAS = {
    # Existing AI attack factors → MITRE ATLAS AML.T00xx categories
    'prompt_injection':             ['ATLAS:AML.T0051 - LLM Prompt Injection'],
    'tool_abuse':                   ['ATLAS:AML.T0054 - LLM Jailbreak', 'ATLAS:AML.T0057 - LLM Plugin Compromise'],
    'sensitive_output_leak':        ['ATLAS:AML.T0043 - Craft Adversarial Data'],
    'model_evasion_adversarial':    ['ATLAS:AML.T0015 - Evade ML Model', 'ATLAS:AML.T0048 - Backdoor ML Model'],
    'training_data_poisoning':      ['ATLAS:AML.T0020 - Poison Training Data'],
    # AI supply chain / model integrity
    'model_supply_chain_tamper':    ['ATLAS:AML.T0010 - ML Supply Chain Compromise'],
    'model_inversion_attack':       ['ATLAS:AML.T0024 - Infer Training Data Membership'],
    'model_extraction':             ['ATLAS:AML.T0030 - Model API Enumeration'],
    # Agent / agentic AI threats
    'agent_goal_hijack':            ['ATLAS:AML.T0051 - LLM Prompt Injection', 'ATLAS:AML.T0054 - LLM Jailbreak'],
    'agent_memory_poisoning':       ['ATLAS:AML.T0020 - Poison Training Data'],
    'agent_tool_misuse':            ['ATLAS:AML.T0057 - LLM Plugin Compromise'],
    # Infrastructure eBPF → ML pipeline attack surface
    'endpoint:ebpf_kprobe_on_secfn': ['ATLAS:AML.T0010 - ML Supply Chain Compromise'],
    # Network fingerprinting aids model server targeting
    'net:jarm_c2_match':            ['ATLAS:AML.T0030 - Model API Enumeration'],
}

FACTOR_TO_OWASP_LLM = {
    # LLM Top 10 2025 (updated from 2023 edition)
    'prompt_injection':             ['LLM01:2025 - Prompt Injection'],
    'sensitive_output_leak':        ['LLM02:2025 - Sensitive Information Disclosure',
                                     'LLM06:2025 - Excessive Agency'],
    'tool_abuse':                   ['LLM06:2025 - Excessive Agency',
                                     'LLM07:2025 - System Prompt Leakage'],
    'model_evasion_adversarial':    ['LLM05:2025 - Improper Output Handling'],
    'training_data_poisoning':      ['LLM04:2025 - Data and Model Poisoning'],
    'model_extraction':             ['LLM10:2025 - Unbounded Consumption'],
    'agent_memory_poisoning':       ['LLM04:2025 - Data and Model Poisoning'],
    'agent_goal_hijack':            ['LLM01:2025 - Prompt Injection'],
    'model_supply_chain_tamper':    ['LLM03:2025 - Supply Chain Vulnerabilities'],
    # NEW 2025 entries not in 2023
    'vector_db_poisoning':          ['LLM08:2025 - Vector and Embedding Weaknesses'],
    'rag_context_injection':        ['LLM08:2025 - Vector and Embedding Weaknesses',
                                     'LLM01:2025 - Prompt Injection'],
    'model_dos_token_flood':        ['LLM10:2025 - Unbounded Consumption'],
    'system_prompt_exfil':          ['LLM07:2025 - System Prompt Leakage'],
    'mcp_tool_injection':           ['LLM01:2025 - Prompt Injection',
                                     'LLM06:2025 - Excessive Agency'],
}

# CASB / DLP factor mappings
FACTOR_TO_MITRE.update({
    'dlp:casb_policy_match':   ['T1213', 'T1530'],
    'dlp:crowdstrike_fp_match': ['T1565', 'T1213'],
})

# ── MITRE ATT&CK v14 / v15 new techniques (2023-2024) ────────────────────────
FACTOR_TO_MITRE.update({
    # T1649 — Steal or Forge Authentication Certificates (ADCS abuse)
    'iam:adcs_cert_request_abuse':        ['T1649'],
    'iam:adcs_esc1_misconfiguration':     ['T1649'],
    'iam:adcs_esc4_template_write':       ['T1649', 'T1484.001'],
    'iam:adcs_golden_cert_forge':         ['T1649', 'T1558'],
    # T1651 — Cloud Administration Command
    'cloud:ssm_run_command_unusual':      ['T1651'],
    'cloud:aws_ssm_command_burst':        ['T1651', 'T1059'],
    'cloud:azure_run_command_privilege':  ['T1651', 'T1098'],
    # T1654 — Log Enumeration
    'cloud:cloudtrail_enumeration':       ['T1654', 'T1087'],
    'cloud:log_analytics_query_burst':    ['T1654'],
    'endpoint:event_log_read_programmatic': ['T1654', 'T1083'],
    # T1657 — Financial Theft (BEC wire fraud, crypto theft)
    'email:bec_wire_transfer_redirect':   ['T1657', 'T1566.003'],
    'cloud:crypto_wallet_api_access':     ['T1657', 'T1552'],
    # T1659 — Content Injection (MITM / adversary-in-the-middle content mod)
    'net:content_injection_mitm':         ['T1659', 'T1557'],
    'net:tls_stripping_inject':           ['T1659', 'T1553'],
    # T1666 — Modify Cloud Compute Configuration
    'cloud:ec2_userdata_modification':    ['T1666'],
    'cloud:vm_extension_script_inject':   ['T1666', 'T1059'],
    'cloud:lambda_env_var_modification':  ['T1666', 'T1552'],
})

# ── Extended eBPF / kernel threat factors ─────────────────────────────────────
FACTOR_TO_MITRE.update({
    'endpoint:ebpf_rootkit_persist':      ['T1014', 'T1547.006', 'T1562.001'],
    'endpoint:ebpf_map_read_large':       ['T1083', 'T1005'],
    'endpoint:ebpf_packet_rewrite':       ['T1565.002', 'T1659'],
    'endpoint:ebpf_perf_buffer_flood':    ['T1499', 'T1562'],
    'endpoint:ebpf_kprobe_on_secfn':      ['T1014', 'T1562.001'],
    'endpoint:ebpf_uprobe_libc':          ['T1055', 'T1014'],
    'endpoint:ebpf_prog_persistent':      ['T1014', 'T1547.006'],
    'endpoint:ebpf_map_pin_suspicious':   ['T1014'],
    'endpoint:bpf_filter_on_socket':      ['T1040', 'T1014'],
})

# ── DKIM / DMARC / ARC email authentication depth factors ────────────────────
FACTOR_TO_MITRE.update({
    'email:dkim_fail_aligned':            ['T1566', 'T1036'],
    'email:dmarc_fail_quarantine':        ['T1566', 'T1036.005'],
    'email:arc_chain_break':              ['T1566', 'T1565'],
    'email:spf_softfail_dmarc_none':      ['T1566'],
    'email:dkim_replay_attack':           ['T1550', 'T1566'],
    'email:dmarc_reject_policy_absent':   ['T1566'],
    'email:bimi_spoof_attempt':           ['T1566', 'T1036'],
})

# ── Network fingerprinting: JARM, JA4+ ───────────────────────────────────────
FACTOR_TO_MITRE.update({
    'net:jarm_c2_match':                  ['T1071.001', 'T1090.001', 'T1573'],
    'net:jarm_novel_server_fp':           ['T1090', 'T1571'],
    'net:ja4_novel_fingerprint':          ['T1071.001', 'T1571'],
    'net:ja4h_suspicious_http':           ['T1071.001'],
    'net:ja4s_server_impersonation':      ['T1557', 'T1573'],
    'net:ja4l_low_latency_c2':            ['T1071.001', 'T1573'],
    'net:ja4_ja3_mismatch':               ['T1036', 'T1565'],
})

# ── BGP hijack, BEC kill-chain, actor-rate, adaptive-cadence C2 ───────────────
# Newer detector factors that had no ATT&CK mapping, so get_all_mappings()
# returned [] and these techniques never surfaced in reports / phase swimlanes.
FACTOR_TO_MITRE.update({
    'network:bgp_route_hijack':               ['T1599'],            # Network Boundary Bridging
    'network:bgp_hijack':                     ['T1599'],            # alias of the above
    'sequence:bec_kill_chain':                ['T1566', 'T1114.003', 'T1534'],  # phish → inbox rule → internal spread
    'actor:script_kiddie_rate':               ['T1595'],            # high-rate active scanning
    'network:c2_jitter_evasion':              ['T1071', 'T1571'],   # app-layer C2 + non-standard port
    'network:adaptive_ewma_regular_cadence':  ['T1071'],            # regular beacon cadence (app-layer C2)
})

# ── 2026 H1 threat coverage: ESXi ransomware, MFA fatigue, AiTM, VPN/IKE, EDR-blinding ──
FACTOR_TO_MITRE.update({
    'impact:esxi_hypervisor_ransomware':  ['T1486'],                # Scattered Spider/UNC3944 ESXi encryption
    'iam:mfa_fatigue_bombing':            ['T1621'],                # MFA push-bombing (STORM-2372)
    'behavior:mfa_fatigue_spike':         ['T1621'],                # ChronoGraph rate-anomaly variant
    'email:aitm_session':                 ['T1557', 'T1539'],       # adversary-in-the-middle + steal web session cookie
    'remote:ike_vpn_exploit':             ['T1190', 'T1133'],       # CVE-2026-50751/-33824 VPN/IKE exploit
    'endpoint:edr_telemetry_gap':         ['T1562.001', 'T1564'],   # eBPF/io_uring telemetry tampering / EDR blinding
    'iam:helpdesk_anomalous_reset':       ['T1098', 'T1556'],       # helpdesk-coerced credential/MFA reset
    'cloud:ses_leaked_key_send':          ['T1078.004', 'T1567'],   # Amazon SES abuse via leaked IAM key
})

def get_all_mappings(factors: list[str]) -> dict[str, list[str]]:
    """Return combined mapping tags: ATT&CK techniques, ATLAS, and OWASP LLM.

    Does not modify existing FACTOR_TO_MITRE usage; provided as a helper.
    """
    mitre: set[str] = set()
    atlas: set[str] = set()
    owasp: set[str] = set()
    for f in factors:
        for t in FACTOR_TO_MITRE.get(f, []):
            mitre.add(t)
        for a in FACTOR_TO_ATLAS.get(f, []):
            atlas.add(a)
        for o in FACTOR_TO_OWASP_LLM.get(f, []):
            owasp.add(o)
    return {
        'mitre': sorted(mitre),
        'atlas': sorted(atlas),
        'owasp_llm': sorted(owasp)
    }
