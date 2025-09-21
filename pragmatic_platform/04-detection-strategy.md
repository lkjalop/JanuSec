# Detection Strategy & Factor Taxonomy

## Principles
- Prefer cheap deterministic filters early.
- Use consistent factor naming: `category:detail`.
- Maintain taxonomy version; include digest in decisions.

## Factor Categories (Initial)
| Category | Examples | Purpose |
|----------|----------|---------|
| infra | `asn_high_risk`, `geo_high_risk`, `suspicious_tld` | Infra risk & geolocation |
| behavior | `behavior:persistence_create`, `behavior:suspicious_spawn` | Sandbox / runtime patterns |
| attack | `attack:T1059`, `attack:T1021` | MITRE techniques |
| asset | `asset_critical:high`, `asset_critical:critical` | Business impact weighting |
| novelty | `novelty_cluster_stable`, `novelty_outlier` | Emerging pattern signaling |
| policy | `exception_allowed`, `requires_approval` | Governance signals |
| quality | `analysis_error`, `module_timeout` | Pipeline health / QC |
| routing | `graph_multi_link`, `cluster_high_cohesion` | Correlation context |

## APT Heuristic Components
1. Stage Accumulation: maintain per-entity stage flags (recon, foothold, lateral, staging, exfiltration).
2. Temporal Expansion: increasing unique host/account/port cardinality with monotonic trend.
3. Low-and-Slow Anomaly Sum: aggregate micro anomalies with decay λ.
4. Infrastructure Consistency: repeated callbacks to stable infra cluster.

Decision trigger when ≥3 distinct stages + expansion score > threshold OR anomaly decay sum crosses limit.

## Cluster Signals
- Stability: `count / (1 + span)`.
- Cohesion: average pairwise Jaccard.
- Novelty Ratio: `novelty_factor_count / total`.

Confidence delta contribution (example weighting):
```
if stability > 0.002 and cohesion > 0.4:
  delta += 0.03
if novelty_ratio > 0.3:
  factors.append('novelty_cluster_significant')
```

## Benign Heuristics
| Condition | Action |
|-----------|--------|
| Known business partner ASN + consistent working-hours pattern | add factor `infra_legit_pattern`, delta -0.05 |
| High-reputation domain & certificate age > 365d | delta -0.02 |
| Long-term stable process hash executed daily (endpoint) | delta -0.04 |

## Temporary Suppression
Short-lived factors (e.g. rollout noise) can be tagged `suppression:rollout_noise` and decayed out of taxonomy after N days.

## Taxonomy Versioning
- `taxonomy.yaml` maintained with semantic version.
- Digest included in `config_digests` and audit.
- Breaking change (rename/remove) increments MINOR.

## Data Needed to Evolve Strategy
- Replay label deltas (missed vs caught) per factor → weight adjustments.
- Factor co-occurrence matrix → detect redundancy.
- False positive concentration analysis → candidate benign heuristic rules.

## Open Questions
1. Should infrastructure clustering produce its own factor (`infra_cluster:<id>`) or remain internal? (Lean: produce only for high-risk clusters.)
2. Represent novelty outliers as separate factor vs modifier? (Prefer explicit factor for transparency.)
