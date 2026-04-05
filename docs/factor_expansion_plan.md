# Factor Expansion Plan (Phase Next)

Target: Increase mapped factors from 96 to ≥120 with STRIDE coverage ≥95% and broaden multi-domain attack reconstruction depth.

## Domains & New Factors

Identity:
- identity:delegated_admin_escalation (elevation, spoofing)
- identity:stale_session_token_reuse (spoofing)
- identity:impossible_time_role_switch (elevation)
- identity:privileged_group_membership_spike (elevation, tampering)

Endpoint:
- endpoint:registry_runkey_multi_variant (tampering, elevation)
- endpoint:signed_binary_rename_execution (tampering, elevation)
- endpoint:persistence_service_install_chain (tampering, elevation)
- endpoint:memory_reflective_loader_pattern (elevation)

Network:
- net:encrypted_dns_volume_outlier (information_disclosure)
- net:uncommon_c2_infrastructure_age (command_and_control, information_disclosure)
- net:http3_quic_covert_channel (command_and_control)
- net:exfil_small_chunk_stitching (information_disclosure, exfiltration)

Cloud:
- cloud:misconfigured_oidc_trust (spoofing, elevation)
- cloud:orphan_secret_key_usage (spoofing, information_disclosure)
- cloud:privilege_policy_inversion (elevation, tampering)
- cloud:shadow_admin_role_creation (elevation)

Remote:
- remote:shared_account_parallel_login (spoofing)
- remote:geoimpossible_jitter_pattern (spoofing, information_disclosure)
- remote:legacy_cipher_suite_access (information_disclosure, tampering)
- remote:stale_vpn_session_reuse (spoofing)

Application/API:
- api:graphql_introspection_abuse (information_disclosure)
- api:open_redirect_chain (spoofing, elevation)
- api:broken_object_layer_priv_escalation (elevation, tampering)
- api:websocket_upgrade_anomaly (tampering)

Data:
- data:mass_schema_read_pattern (information_disclosure)
- data:shadow_backup_creation (information_disclosure, tampering)
- data:integrity_hash_chain_mismatch (tampering)
- data:anomalous_row_level_access_burst (information_disclosure, elevation)

Email:
- email:dkim_mismatch_sequence (spoofing)
- email:oauth_scope_expansion (spoofing, elevation)
- email:mailbox_forwarding_rule_escape (information_disclosure)
- email:encrypted_attachment_suspicious (information_disclosure)

Meta (correlation / multi-stage):
- meta:multi_vector_priv_exfil_chain (information_disclosure, elevation, exfiltration)
- meta:multi_domain_escalation_bridge (elevation, lateral_movement)
- meta:privilege_persistence_lateral_fork (elevation, persistence)
- meta:lateral_exfil_privilege_progression (lateral_movement, exfiltration, elevation)

## STRIDE Coverage Strategy
Each factor includes ≥1 STRIDE category; multi-domain/meta factors carry combined categories to boost category richness without over-weighting single-domain noise.

## Mapping Guidelines
- DREAD: Use conservative mid-values; raise damage on exfiltration / privilege.
- MITRE: Associate representative techniques (e.g., T1078, T1041) for reconstruction weighting; placeholder if not mapped yet.
- PASTA Stages: Rough alignment (initial_access 3–4; lateral 4–5; exfil 6; impact 7).

## Next Steps
1. Insert new factors into taxonomy map with stride + minimal dread + mitre placeholders.
2. Re-run `tests/test_factor_coverage.py` to confirm count ≥120.
3. Adjust hopgraph scoring to include domain diversity coefficient.
4. Integrate adaptive EWMA alpha once diversity weighting validated.
5. Document updated API usage & add changelog entry.
