# HopGraph Attack Reconstruction — Consolidated Update (Backend + UI + Playbooks)

Purpose: Single reference for all recent HopGraph and CSV Analyzer additions to enable quick review and verification.

## Scope
- Attack reconstruction factors across 8 domains (existing + new): 120 factors total
- CSV Analyzer (single and multi-upload) improvements and UX
- Session persistence backend hardening (JSON + SQLite)
- SOAR playbooks wiring to factors
- Threat modeling and explainability overlays (MITRE, narrative, factor reasons)

---

## Factors by Domain (120 total)

Below lists include the original 80 and the 40 new additions. Descriptions live in `src/config/factor_descriptions_ext.json` and canonical mappings in `src/core/mappings/factor_to_mitre.py`.

Files:
- Descriptions overlay: `src/config/factor_descriptions_ext.json`
- MITRE map: `src/core/mappings/factor_to_mitre.py`

### Identity (15)
- identity:kerberos_s4u_abuse
- identity:mfa_fatigue_mismatch
- identity:role_mutation_burst
- identity:conditional_access_drift
- identity:session_stitching_anomaly
- identity:pass_the_cookie_reuse
- identity:oauth_refresh_storm
- identity:service_principal_key_aged
- identity:privilege_escalation_path_found
- identity:impossible_mfa_device_change
- identity:password_spray_slow_burn (NEW)
- identity:delegated_admin_grant_spike (NEW)
- identity:stale_session_reuse_chain (NEW)
- identity:idp_app_impersonation_risk (NEW)
- identity:impossible_travel_with_device_bind (NEW)

### Endpoint (15)
- endpoint:code_sign_trust_anomaly
- endpoint:dll_sideload_rare_path
- endpoint:driver_load_rare_signature
- endpoint:lateral_exec_remote_tool
- endpoint:persistence_surface_multi
- endpoint:injection_suspicious_memory
- endpoint:lolbin_chain_mshta_rundll32
- endpoint:tamper_edr_registration
- endpoint:credential_dump_tool_artifacts
- endpoint:unsigned_driver_install_flow
- endpoint:edr_uninstall_or_tamper_flow (NEW)
- endpoint:signed_binary_proxy_abuse (NEW)
- endpoint:lsa_protection_disabled (NEW)
- endpoint:persistence_masquerade_service (NEW)
- endpoint:rare_parent_child_combo (NEW)

### Network (15)
- net:ja3_ja4_novel_pair
- net:sni_dns_nx_spike
- net:tls_cert_chain_anomaly
- net:flow_microcluster_exfil
- net:port_protocol_misuse
- net:doh_tunnel_candidate
- net:socks_proxy_behavior_detected
- net:dga_domain_features
- net:tor_outbound_contact
- net:ip_fragment_evasion_pattern
- net:quic_fingerprint_novelty (NEW)
- net:tls_version_downgrade_attempt (NEW)
- net:dot_tunnel_candidate (NEW)
- net:cdn_fronting_suspect (NEW)
- net:ssh_banner_anomaly (NEW)

### Cloud (15)
- cloud:cross_account_trust_chain
- cloud:kms_secrets_access_anomaly
- cloud:serverless_trigger_exposure
- cloud:container_ctrlplane_risky_binding
- cloud:egress_path_risk
- cloud:iam_policy_shadow_admin
- cloud:pre_signed_url_abuse
- cloud:metadata_service_abuse
- cloud:cross_region_replication_unapproved
- cloud:security_group_broad_egress
- cloud:resource_policy_escalation_path (NEW)
- cloud:logging_gap_or_disable (NEW)
- cloud:public_storage_acl_change (NEW)
- cloud:lambda_secret_leak_env (NEW)
- cloud:k8s_api_anon_access_attempt (NEW)

### Remote Access (15)
- remote:handshake_reuse_key
- remote:vpn_mfa_mode_anomaly
- remote:jump_host_chain
- remote:remote_tooling_session
- remote:geo_velocity_asn_risk
- remote:rdp_bruteforce_distributed
- remote:ssh_password_auth_enabled_risk
- remote:legacy_vpn_proto_in_use
- remote:bastion_sudo_escalation_sequence
- remote:reused_ssh_private_key_fingerprint
- remote:rdp_nla_disabled (NEW)
- remote:anydesk_id_reuse (NEW)
- remote:ssh_agent_forwarding_misuse (NEW)
- remote:vpn_split_tunnel_exfil (NEW)
- remote:clipboard_file_transfer_burst (NEW)

### API (15)
- api:schema_drift_high_risk
- api:client_fp_replay
- api:waf_ids_signal_join
- api:mtls_client_cert_drift
- api:key_lifecycle_anomaly
- api:bola_detected
- api:rate_limit_bypass_pattern
- api:jwt_alg_confusion_none
- api:mass_assignment_attempt
- api:insecure_deserialization_gadget
- api:graphql_introspection_exposed (NEW)
- api:cors_wildcard_with_creds (NEW)
- api:pii_in_params_detected (NEW)
- api:oauth_pkce_missing_pattern (NEW)
- api:weak_hsts_tls_policy (NEW)

### Data (15)
- data:query_shape_rare_sequence
- data:inventory_sensitivity_link
- data:egress_reconciliation_gap
- data:snapshot_diff_unexpected
- data:secrets_access_anomaly
- data:pseudonymization_gap_detected
- data:pii_bulk_export_attempt
- data:tls_in_transit_missing
- data:encryption_at_rest_mismatch
- data:data_tag_mismatch_access
- data:staging_table_exfil_flow (NEW)
- data:dlp_policy_bypass_attempt (NEW)
- data:backup_snapshot_external_share (NEW)
- data:key_usage_anomaly_kms (NEW)
- data:row_level_policy_gap (NEW)

### Email (15)
- email:auth_alignment_fail
- email:sandbox_lineage_c2
- email:mailbox_rule_burst
- email:oauth_consent_suspicious
- email:reply_chain_hijack
- email:display_name_impersonation
- email:thread_hijack_lateral_spread
- email:credential_harvest_landing_detected
- email:qr_phish_lure
- email:oauth_device_code_abuse
- email:smtp_auth_residential_asn (NEW)
- email:shortener_chain_bypass (NEW)
- email:dkim_flap_campaign_pattern (NEW)
- email:risky_publisher_oauth_app (NEW)
- email:sender_tld_spike_high_risk (NEW)

---

## SOAR Playbooks and Triggers

Files: `src/data/playbooks/`
- 01_malware_validation.json — manual validation
- 02_domain_triage.json — domain triage
- 03_c2_block.json — C2 block
- 04_isolate_host.json — isolate endpoint
- 05_vex_suppress.json — suppress via VEX
- 06_notify_exec.json — notify exec
- 07_token_replay_revoke_sessions.json — trigger: identity:pass_the_cookie_reuse
- 08_network_doh_tor_block.json — trigger: net:doh_tunnel_candidate or net:tor_outbound_contact
- 09_cloud_shadow_admin_rollback.json — trigger: cloud:iam_policy_shadow_admin
- 10_endpoint_unsigned_driver_quarantine.json — trigger: endpoint:unsigned_driver_install_flow
- 11_email_mailbox_rule_burst_reset.json — trigger: email:mailbox_rule_burst

Runner support (dry-run stubs): `src/soar/runner.py`
- revoke_sessions, quarantine_file, policy_rollback, disable_mailbox_rule, reset_credentials, block_ip, notify, open_case

---

## CSV Analyzer (Multi-Source) — UI/UX Improvements

File: `frontend/static/csv_multi_analyzer.html`

New features:
- Mapping presets by domain/log-type (EDR, VPN, API Gateway, CloudTrail, Email, Zeek). Controls: `#presetSelect` + `#btnApplyPreset`.
- Rarity & Baseline (EWMA) panel: `#rarityList` shows rare values per canonical field with EWMA delta vs local baseline (stored in `localStorage.csvMultiEwma`).
- Factor overlay panel: `#factorOverlay` lists emitted factors with reasons and referenced canonical fields.
- Pivot micrograph seed: clicking a rarity badge updates `#graphCanvas` with a pivot focus note (stub UI hook for deeper graphing).

Existing panels refreshed:
- Risk narrative, correlation heatmap, intersections, and framework mapping placeholders render after build.

Single and multi-upload flow:
- Multi-upload via `#fileInput` posts to `/api/v1/upload/files`, returns `sessions` used by `/api/v1/graph/session/build`.
- Mapping editor auto-suggests canonical columns; presets allow quick mapping overrides.

---

## Backend: Graph Session Persistence Hardening

Files:
- Store abstraction: `src/api/session_store.py` (JSON default, SQLite optional)
- API handlers: `src/api/graph_sessions.py`
- App scheduler wiring: `src/api/app.py` (cleanup loop calls store.cleanup + JSON legacy cleanup)

Environment variables:
- `SESSION_BACKEND` = `json` | `sqlite` (default: json)
- `SESSION_PERSIST_DIR` (default: `data/sessions`)
- `SESSION_PERSIST_SQLITE_PATH` (default: `data/sessions/sessions.db`)
- `SESSION_TTL_SECONDS` (default: `86400`)
- `SESSION_CLEAN_INTERVAL_SECONDS` (default: `0`, disabled)

Behavior:
- GET/POST build/load use `get_session_store()`; cache is reset before use to respect per-test env changes.
- SQLite schema auto-created; TTL enforced via `updated_at`. Cleanup loop prunes expired rows/files.

Tests:
- `tests/test_graph_session_sqlite.py` (roundtrip + TTL) — fixed by resetting store cache and ensuring per-path schema.
- New: `tests/test_factor_descriptions_ext.py` — checks newly added factor overlay keys available.
- New: `tests/playwright/test_multi_analyzer_presets.spec.js` — verifies EDR preset maps `sha256` → `file_hash`.

---

## Threat Modeling & Explainability

- Factor descriptions overlay: extend without editing canonical file via `src/config/factor_descriptions_ext.json`.
- MITRE ATT&CK mappings updated for all new factors: `src/core/mappings/factor_to_mitre.py`.
- UI narrative shows verdict/confidence and top factors; overlay panel exposes “why” (refs to canonical fields found in reasons).

---

## Quick Verification Checklist

- UI
  - Open `http://localhost:8080/static/csv_multi_analyzer.html`
  - Upload `tests/playwright/fixtures/test_row.csv`
  - Apply “Endpoint/EDR” preset → verify `sha256` mapped to `file_hash`
  - Build graph → heatmap, intersections, rarity and factor overlay populate

- Playbooks
  - Inspect `src/data/playbooks/*.json` for triggers and steps

- Persistence
  - Set `SESSION_BACKEND=sqlite` and `SESSION_PERSIST_SQLITE_PATH=./data/sessions/sessions.db`
  - `POST /api/v1/graph/session/build` → row inserted; `GET` round-trips

---

## File Index

- Factors & Mappings
  - Descriptions overlay: `src/config/factor_descriptions_ext.json`
  - MITRE mappings: `src/core/mappings/factor_to_mitre.py`
- UI
  - CSV Multi Analyzer: `frontend/static/csv_multi_analyzer.html`
- Backend
  - Session Store: `src/api/session_store.py`
  - Graph Sessions API: `src/api/graph_sessions.py`
  - App Wiring (cleanup): `src/api/app.py`
- Playbooks
  - `src/data/playbooks/01_...json` through `11_...json`
- Tests
  - Unit: `tests/test_factor_descriptions_ext.py`
  - Playwright: `tests/playwright/test_multi_analyzer_presets.spec.js`

---

## Notes / Follow-ups
- Pivot micrograph is a stub UI hook; can be extended to render neighborhood graph per selected value.
- Rarity EWMA baseline persists locally per browser; server-side baseline could be added in future.
- Factor overlay row-level tagging can be deepened by passing row provenance or matched value sets from backend.
