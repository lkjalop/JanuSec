# BACKLOG: HopGraph, eBPF, BGP, Persistence (Prioritized)

This backlog is derived from the repo scan and recent changes. Tasks are ordered by priority and include file mappings and rough estimates.

## High priority (now)

1. Identity consolidation & API facade
   - Create `src/core/graph/api_hopgraph.py` to unify `GLOBAL_*` accessors and provide read-only facades.
   - Files: `identity_hopgraph.py`, `cloud_hopgraph.py`, `network_hopgraph.py`
   - Effort: 2-4 hours

2. Identity snapshot persistence (completed: basic JSON)
   - Added `save_snapshot(path)` / `load_snapshot(path)` in `identity_hopgraph.py`.
   - Files: `src/core/graph/identity_hopgraph.py`, `tests/test_identity_snapshot.py`
   - Effort: 4-8 hours (done - basic)

3. Wire BGP client into network graph (completed)
   - BGP prefixes push `route:{prefix}` nodes into `GLOBAL_NETWORK_GRAPH`.
   - Files: `src/integrations/bgp_client.py`, `src/core/graph/network_hopgraph.py`, `tests/test_bgp_network_wiring.py`, `tests/test_bgp_metadata_edges.py`
   - Effort: 3-6 hours (done - basic edges)

4. eBPF/Falco smoke harness (completed)
   - Add `tests/test_ebpf_smoke.py` which runs `ebpf_analysis_stage` with a sample Falco event.
   - Files: `src/core/event_pipeline/stages/ebpf_analysis.py`, `tests/test_ebpf_smoke.py`
   - Effort: 2-4 hours (done)

## Medium priority

5. Cloud posture connectors (AWS first)
   - Implement `src/integrations/cloud_aws.py` to fetch inventory, map to standardized resources, and call `GLOBAL_CLOUD_GRAPH.ingest_resource`.
   - Files: `src/integrations/cloud_aws.py`, `src/core/graph/cloud_hopgraph.py`, tests
   - Effort: 8-16 hours

6. SBOM / image digest mapping
   - Helper that maps image digest / binary sha to SBOM and CVE lookup.
   - Files: `src/integrations/sbom.py` or inside `cloud_hopgraph.py`
   - Effort: 6-10 hours

7. Network graph aging/prune tuning and load testing
   - Add periodic prune loop or external scheduler and benchmarks.
   - Files: `network_hopgraph.py`
   - Effort: 4-8 hours

## Lower priority

8. TFT experiment (optional)
   - Add experiments/tft_proof_of_concept.py and training pipeline (heavy).
   - Effort: 2-4 weeks

9. Full hopgraph consolidation (merge lite/light/enhanced variants)
   - Large refactor, ensure tests cover all behaviors.
   - Effort: 2-4 weeks

10. High-Availability Redis Cache (future enterprise requirement)
   - Introduce Redis-backed write-through cache layer for HopGraph nodes/edges and dedup service.
   - Support primary/replica with automatic failover (e.g., Redis Sentinel or managed service).
   - Use Redis pub/sub for invalidation events when multi-process workers mutate graph state.
   - Effort: 1-2 weeks (baseline), +1 week for HA + failover testing.

11. Redis-backed Dedup Service Extension
   - Extend `DedupService` to optionally store keys in Redis for cross-worker and horizontal scaling consistency.
   - Add LUA script for atomic reserve+check to minimize race conditions.
   - Metrics: latency, hit ratio, suppression count across cluster.
   - Effort: 1 week.

---

If you'd like I can open PRs for the completed small items (`identity snapshot`, `bgp wiring`, `ebpf smoke`) and add the demo script `scripts/demo_tools.py` to the repo for maintainers to run.

## Added Factor Stubs (8 domains × 5)

- Identity: kerberos_s4u_abuse, mfa_fatigue_mismatch, role_mutation_burst, conditional_access_drift, session_stitching_anomaly
- Endpoint: code_sign_trust_anomaly, dll_sideload_rare_path, driver_load_rare_signature, lateral_exec_remote_tool, persistence_surface_multi
- Network: ja3_ja4_novel_pair, sni_dns_nx_spike, tls_cert_chain_anomaly, flow_microcluster_exfil, port_protocol_misuse
- Cloud: cross_account_trust_chain, kms_secrets_access_anomaly, serverless_trigger_exposure, container_ctrlplane_risky_binding, egress_path_risk
- Remote Access: handshake_reuse_key, vpn_mfa_mode_anomaly, jump_host_chain, remote_tooling_session, geo_velocity_asn_risk
- Application/API: schema_drift_high_risk, client_fp_replay, waf_ids_signal_join, mtls_client_cert_drift, key_lifecycle_anomaly
- Data: query_shape_rare_sequence, inventory_sensitivity_link, egress_reconciliation_gap, snapshot_diff_unexpected, secrets_access_anomaly
- Email: auth_alignment_fail, sandbox_lineage_c2, mailbox_rule_burst, oauth_consent_suspicious, reply_chain_hijack

Notes
- Descriptions live in `src/config/factor_descriptions_ext.json` (non-invasive overlay).
- STRIDE/DREAD/MITRE/PASTA/CVSS/control mappings added to `src/core/threat_modeling/factor_taxonomy.py`.
