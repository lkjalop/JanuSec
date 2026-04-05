# Detector Taxonomy Reference

| Factor | Description | Confidence Basis | Typical Remediation |
|--------|-------------|------------------|---------------------|
| endpoint:unsigned_exec | Unsigned binary execution observed | Rarity + unsigned flag | Verify binary origin, enforce signing policy |
| identity:role_mutation_burst | Rapid succession of role changes | Count of mutations in window | Review IAM change approvals |
| data:large_extract | Large data export volume anomaly (EWMA) | Deviation from EWMA mean | Investigate destination & user intent |
| cloud:kms_secrets_access_anomaly | Spike in secrets manager/KMS access | Sliding window spike | Audit key usage & recent deployments |
| remote:jump_host_chain | Potential remote access hop chain | Sequential remote_access edges | Confirm lateral movement legitimacy |
| multi_source_correlation | Overlap across multiple session batches | Diversity + overlap density | Escalate multi-source investigation |
| entity_diversity_high | High variety of entities in batch correlation | Diversity score threshold | Assess for broad unauthorized access |
| batch_missing | Referenced batch not found on server | Missing artifact detection | Re-upload or validate ingestion pipeline |
| network:dns_exfil | Excessive unique domain queries indicating exfil | Unique domains/minute vs baseline | Block suspicious resolver, inspect payload |
| file:file_hash_rarity | Rare file hash executed/uploaded | Global frequency below threshold | Scan file, validate source & distribute IOC |

Confidence Scaling Guidelines:
- Base score starts at 0.4 for a single medium-severity factor.
- Add 0.1–0.2 for strong corroborating factors (chain logic combines multi_source_correlation + rarity + burst).
- Cap at 0.95 absent explicit critical exploit evidence.

Remediation Notes:
- Combine multiple related factors before escalating (see factor chaining prototype).
- Rarity factors depend on baseline corpus; tune thresholds in `TUNING_GUIDE.md`.
