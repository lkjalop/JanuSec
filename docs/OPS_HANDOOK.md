# Ops Handbook & Quick Start Extensions

This handbook summarizes operational tuning, key environment variables, replay workflows, and performance guard rails for the platform.

## Core Concepts
- Session Builder: `/api/v1/graph/session/build` aggregates file batches and detectors into a correlated summary with confidence and chain_explanation.
- Detectors: DNS exfil (`dns_exfil`), File hash rarity (`file_hash_rarity`), ASN rarity, beacon periodicity.
- Confidence: Base heuristics + optional weighted combiner (env-driven) + detector uplift (product/mean combination).
- Persistence: Sessions stored under `SESSION_PERSIST_DIR` and file custody artifacts under `FILE_BATCH_CUSTODY_PATH`.

## Key Environment Variables
| Variable | Purpose | Default |
|----------|---------|---------|
| FILE_HASH_HISTORY_MAXLEN | Per-hash timestamp deque length bound | 200 |
| FILE_HASH_HISTORY_MAX_KEYS | Max distinct hash keys retained (prune smallest) | 5000 |
| FILE_HASH_HISTORY_TTL_SECONDS | TTL for individual hash timestamps | 604800 (7d) |
| FILE_HASH_DECAY_SECONDS | Exponential decay tau for rarity counts | 0 (disabled) |
| NX_TRACKER_MAX_PRODUCERS | Max distinct NXDOMAIN producers tracked | 200 |
| ZEEK_NXDOMAIN_RATE_THRESHOLD | NXDOMAIN ratio threshold baseline | 0.35 |
| FACTOR_CONFIDENCE_WEIGHTS | Inline JSON mapping factor->weight | (empty) |
| FACTOR_CONFIDENCE_WEIGHTS_PATH | External JSON/YAML weights file | (unset) |
| FACTOR_LABELS_PATH | Persistence path for factor FP labels | data/factors_labels.json |
| CDN_ALLOWLIST_PATH | Additional DNS CDN allowlist domains file | (unset) |
| DNS_CDN_WHITELIST | Comma whitelist for NX/CDN skip | cloudfront.net,... |

## Confidence Weighting
Provide a JSON/YAML mapping: `{"high_entropy": 1.2, "asn_rare": 0.8, "dns_exfil": 1.5, "*": 0.5}`. The `*` acts as a fallback weight.
- Weighted confidence = sum(score * weight)/sum(weights); existing heuristic confidence is max-blended.
- Explanation block `chain_explanation` lists top contributors.

## False-Positive Labeling
Endpoint: `POST /api/v1/factors/label` payload:
```
{ "session_id": "session-123", "factor": "dns_exfil", "label": "false_positive", "reason": "Legitimate CDN rotation" }
```
- Stored under `runtime.fp_labels` and persisted to `FACTOR_LABELS_PATH`.
- For `false_positive`/`suppressed` we auto-toggle observe flag (best-effort) via `set_observed`.
- List labels: `GET /api/v1/factors/labels?session_id=...`.

## Replay Pipeline
`GET /api/v1/replay?from=<epoch>&to=<epoch>&reprocess=1` loads custody JSONL events in time window and re-ingests them (graph correlation) when `reprocess=1`.
- Useful for retroactive detector improvements and HopGraph rebuilds.
- Safeguard: `limit` query auto-caps at 5000 events.

## Memory & Size Guard Rails
- Hash history pruning executed in session cleanup loop: TTL -> max keys -> smallest removal.
- NX producer cap prunes smallest sample producers beyond `NX_TRACKER_MAX_PRODUCERS`.
- Decay (tau) reduces effective historical counts without immediate deletion for long-lived hashes.

## Performance Load Testing
Script: `scripts/load_test_events.py`.
```
python scripts/load_test_events.py --url http://localhost:8080 --api-key devkey123 --events 10000 --session-build --session-every 2000
```
Outputs JSON summary with EPS, latency distribution, sessions built.

## Operational Tuning Checklist
1. Size bounds: set `FILE_HASH_HISTORY_MAX_KEYS` based on expected daily unique file hash volume.
2. Decay: enable `FILE_HASH_DECAY_SECONDS` (e.g. 86400) to weight recent file hash observations heavier.
3. NX threshold: adjust `ZEEK_NXDOMAIN_RATE_THRESHOLD` if environment has high legitimate NX noise.
4. Confidence Weights: supply domain-specific risk weighting to emphasize critical factors.
5. Cleanup Cadence: configure `SESSION_CLEAN_INTERVAL_SECONDS` (e.g. 900) for regular pruning.
6. Replay: use `/api/v1/replay` after model/detector updates to reclassify historical windows.
7. FP Governance: regularly export FP labels for review, re-enable factors after tuning.

## Deployment Quick Start Extensions
- High-volume mode: increase `FILE_HASH_HISTORY_MAX_KEYS`, enable decay, shorten TTL (e.g. 3d) for memory constraints.
- Low-latency mode: disable replay reprocess during peak hours; schedule outside business hours.
- Strict auth: enable `STRICT_API_KEY_ENFORCEMENT=1` and configure per-key scopes (future extension point).
- Observability: scrape Prometheus `detector_factor_total` and `session_confidence` histograms; alert on high `dns_exfil` factor surge.

## Future Recommendations
- Add factor maturity scoring integrated into chain_explanation.
- Persist replay provenance (replay batch id) for audit trail.
- Per-tenant segmentation of hash/NX trackers.
- Rate-limited FP labeling endpoint for abuse resistance.

## Troubleshooting
| Symptom | Cause | Mitigation |
|---------|-------|------------|
| High memory usage | Hash key explosion | Lower `FILE_HASH_HISTORY_MAX_KEYS`, raise decay, reduce TTL |
| Frequent DNS exfil alerts | Legitimate CDN variety | Expand CDN allowlist file |
| Confidence stuck low | Weight config missing | Provide weights or adjust heuristics |
| Replay slow | Large custody file | Narrow time window or disable reprocess flag |

## Versioning
This handbook accompanies branch `feature/hopgraph-persistence-and-tests`. Keep docs updated with each detector addition or env var change.
