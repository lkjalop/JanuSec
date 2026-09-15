# JanuSec Baseline 80 Factors (Domain Coverage 10 each)

This curated baseline selects 10 representative factors per domain from the unified taxonomy to reach an initial 80 for cross-mapping (MITRE / STRIDE / PASTA / CVSS / KEV-candidate / Maestro / DREAD / Compliance). Higher-depth / specialized factors from the extended taxonomy (>120) remain available but are not required for the MVP cross-framework matrix.

## Identity (10)
identity:kerberos_s4u_abuse
identity:mfa_fatigue_mismatch
identity:role_mutation_burst
identity:conditional_access_drift
identity:session_stitching_anomaly
identity:pass_the_cookie_reuse
identity:service_principal_key_aged
identity:privilege_escalation_path_found
identity:impossible_mfa_device_change
identity:delegated_admin_escalation

## Endpoint (10)
endpoint:code_sign_trust_anomaly
endpoint:dll_sideload_rare_path
endpoint:driver_load_rare_signature
endpoint:lateral_exec_remote_tool
endpoint:persistence_surface_multi
endpoint:injection_suspicious_memory
endpoint:lolbin_chain_mshta_rundll32
endpoint:tamper_edr_registration
endpoint:credential_dump_tool_artifacts
endpoint:unsigned_driver_install_flow

## Network (10)
net:beacon_periodic
net:doh_tunnel_candidate
net:ja3_ja4_novel_pair
net:sni_dns_nx_spike
net:tls_cert_chain_anomaly
net:flow_microcluster_exfil
net:port_protocol_misuse
net:tor_outbound_contact
net:dga_domain_features
net:ip_fragment_evasion_pattern

## Cloud (10)
cloud:public_bucket
cloud:cross_account_trust_chain
cloud:kms_secrets_access_anomaly
cloud:serverless_trigger_exposure
cloud:container_ctrlplane_risky_binding
cloud:egress_path_risk
cloud:iam_policy_shadow_admin
cloud:metadata_service_abuse
cloud:pre_signed_url_abuse
cloud:security_group_broad_egress

## Remote Access (10)
remote:no_mfa
remote:handshake_reuse_key
remote:vpn_mfa_mode_anomaly
remote:jump_host_chain
remote:remote_tooling_session
remote:geo_velocity_asn_risk
remote:rdp_bruteforce_distributed
remote:ssh_password_auth_enabled_risk
remote:legacy_vpn_proto_in_use
remote:bastion_sudo_escalation_sequence

## Application/API (10)
api:api_abuse
api:schema_drift_high_risk
api:client_fp_replay
api:mtls_client_cert_drift
api:key_lifecycle_anomaly
api:bola_detected
api:jwt_alg_confusion_none
api:mass_assignment_attempt
api:insecure_deserialization_gadget
api:rate_limit_bypass_pattern

## Data (10)
data:large_extract
data:query_shape_rare_sequence
data:inventory_sensitivity_link
data:egress_reconciliation_gap
data:snapshot_diff_unexpected
data:secrets_access_anomaly
data:pii_bulk_export_attempt
data:anomalous_row_level_access_burst
data:integrity_hash_chain_mismatch
data:pseudonymization_gap_detected

## Email (10)
email:auth_alignment_fail
email:sandbox_lineage_c2
email:mailbox_rule_burst
email:oauth_consent_suspicious
email:reply_chain_hijack
email:display_name_impersonation
email:thread_hijack_lateral_spread
email:credential_harvest_landing_detected
email:qr_phish_lure
email:dkim_mismatch_sequence

---
Validation: run `python scripts/validate_factor_mappings.py` to confirm full mapping keys present. Synthetic correlation/meta factors excluded from baseline list.
