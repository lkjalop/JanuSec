# Kill Chain Improvement Mapping (Current vs Target)

| Stage | Current Coverage | Gaps | New Factors (Spec IDs) | Target Metrics | Mitigation Enhancements |
|-------|------------------|------|------------------------|----------------|-------------------------|
| Reconnaissance | Limited (port scan, DNS enum) | Lacks API discovery, repo sweep, credential spray correlation | api:discovery_pattern_scan, data:multiple_repository_sweep, iam:abnormal_role_grant_volume, api:shadow_endpoint_access | >85% of benign discovery separated (FP <10%) | Adaptive rate-limit, auto sensor suggestion |
| Initial Access | Strong | MFA bypass chain not explicit | iam:mfa_bypass_pattern, email:credential_phish_link_pattern, email:bec_likely_thread_hijack | Detect >90% phishing variants with <15% FP | Auto quarantine + just-in-time MFA re-enable |
| Execution | Excellent | Rare method sequences partially inferred | api:rare_method_combo, api:response_schema_anomaly | Sequence rarity coverage >80% | Dynamic WAF verb restriction |
| Persistence | Strong | Shadow resource creation untracked | cloud:shadow_resource_creation | >75% unauthorized resource attempts flagged | Tag enforcement + IaC diff validation |
| Privilege Escalation | Good | Multi-step chain escalation & dormant privilege activation | iam:privilege_chain_escalation, iam:unused_privilege_activation, cloud:privilege_drift | >90% high-risk escalations detected within 10m | Automatic role rollback suggestion |
| Credential Access | Good | Cross-IP token reuse | api:auth_token_reuse_cross_ip, email:impossible_login_sequence, cloud:unused_secret_usage | Token theft detection sensitivity >85% | Immediate token revocation flow |
| Lateral Movement | Excellent | Multi-region lateral in cloud | cloud:multi_region_lateral_path | Cloud lateral detection >70% | Region scope restriction automation |
| Command & Control | Excellent | Distributed/NAT C2 continuity >72h | (Vector/Graph persistence future) | Maintain chain continuity 96h | Graph stitch + embedding similarity alert |
| Exfiltration | Moderate | Composite staging+compression+egress chain weak | data:staging_volume_spike, data:egress_protocol_rare, exfil:chain_confidence | <5m detection from staging onset | Egress block + dataset quarantine |
| Impact | Limited | Encryption burst & service disable | impact:ransomware_encrypt_burst, impact:service_disable_sequence | Detect encryption <3m from onset | Host isolation + restore plan suggestion |

## Metric Baselines & Targets
- Recon Distinct Scan Separation Rate: CURRENT ~50% → TARGET 85%.
- Exfiltration Time to Flag: CURRENT ~20m → TARGET <5m.
- Impact Time to Isolation: CURRENT N/A → TARGET <3m.
- Priv Esc Chain Detection Latency: CURRENT ~30m → TARGET <10m.

## Data Dependencies
| Factor | Required Telemetry | Priority |
|--------|--------------------|----------|
| iam:privilege_chain_escalation | IAM role grant stream, privilege delta metrics | High |
| data:staging_volume_spike | Directory size deltas, file entropy | High |
| api:discovery_pattern_scan | API status codes, unique path attempts | High |
| email:bec_likely_thread_hijack | Thread lineage, domain age, keyword scores | Medium |
| cloud:privilege_drift | Policy diff risk quantification | High |
| impact:ransomware_encrypt_burst | File write events + extension changes | High |

## Sequencing Roadmap (Quarterly)
1. Telemetry foundation (IAM diffs, staging volume, API gateway errors).  
2. Factor deployment + baseline threshold tuning (adaptive EWMA).  
3. Embedding + Neo4j chain extension for long-horizon continuity.  
4. Automated mitigation orchestration (role rollback, ACL revert, egress throttle).  
5. Compliance overlay mapping (NIST CSF alignment per factor cluster).  

## Validation Strategy
- Unit tests per factor threshold edge.
- Simulation harness: synthetic multi-stage exfil chain to assert composite factor.
- Replay historical logs (if available) to measure pre/post false positive rate.

Version: 1
