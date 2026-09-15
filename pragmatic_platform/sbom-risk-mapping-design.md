# SBOM Risk Mapping & Correlation Design

## Objective
Translate software supply chain exposure (component + vulnerability data) into bounded, explainable scoring factors (`sbom:*`) that influence artifact decisions without overpowering behavioral evidence.

## Scope (Phase 1)
1. Ingest CycloneDX SBOMs (already implemented: component registry).
2. Parse `vulnerabilities` arrays (if present) and aggregate per execution hash / artifact.
3. Derive severity bucket counts & density metrics.
4. Emit summarized factors + metadata for scoring stage.

## Data Model Additions
```
SbomVulnAggregate {
  exec_hash: str,                # tie to artifact / deployment snapshot
  component_id: str,
  severity_counts: {critical:int, high:int, medium:int, low:int, unknown:int},
  cvss_max: float?,
  last_seen: ts,
  total_components: int,
  vulnerable_components: int
}
```
In-memory index keyed by `exec_hash` with rolling update. Persistence optional (JSONL) for restart continuity.

## Factor Set (Initial)
| Factor | Trigger | Notes |
|--------|---------|-------|
| `sbom:cve_critical` | ≥1 critical vulnerability present | Single presence; no count suffix to avoid factor explosion |
| `sbom:cve_high_density` | (high + critical) / components ≥ 0.05 AND ≥3 total | Density gate to avoid tiny noise packages |
| `sbom:cve_backlog_large` | (medium+high+critical) ≥ 25 | Signals operational debt |
| `sbom:vuln_age_stale` | Oldest unresolved vuln age ≥ 180d | Aging risk indicator |
| `sbom:supply_chain_drift` | Exec hash drift between consecutive ingests with net +X vulnerable comps | Leverages existing drift tracking |
| `sbom:cwe_hotspot` | ≥2 vulns map to same high-impact CWE cluster (config list) | CWE cluster mapping table |

Optional (Phase 2) if needed:
| `sbom:exploit_predicted` | External feed / EPSS ≥ threshold | Requires external scoring feed |

## Weighting Strategy (Guardrails)
- SBOM-derived cumulative positive confidence contribution capped at +0.20 (≈ one enrichment module) to prevent overshadowing live behavior.
- Individual factor suggested base deltas (pre-calibration):
  - `sbom:cve_critical`: +0.08
  - `sbom:cve_high_density`: +0.05
  - `sbom:cve_backlog_large`: +0.03
  - `sbom:vuln_age_stale`: +0.02
  - `sbom:supply_chain_drift`: +0.04 (contextual, may co-occur)
  - `sbom:cwe_hotspot`: +0.04

If cumulative > 0.20, scale proportionally: `scaled_delta = (delta / sum_positive) * 0.20`.

## Mapping Vulnerabilities → CWE → MITRE / STRIDE
1. Parse each vulnerability's CWE list (if provided). Maintain mapping table:
   `cwe_cluster.yaml` with clusters (ex: `injection`, `deserialization`, `rce_vector`).
2. Each cluster maps to MITRE technique tags (e.g., `T1190` for injection/exploit public-facing app) and STRIDE categories (e.g., Tampering, Elevation of Privilege).
3. When `cwe_hotspot` triggers, append corresponding MITRE technique factors (`attack:T1190`) only if not already present to avoid duplication.

## Compliance Correlation (Phase 2)
Derive optional compliance mapping metrics (not confidence deltas): number of unresolved high+critical mapping to controls (e.g., NIST CSF PR.IP-12). Exposed via metadata, not factors (prevents compliance noise polluting scoring).

## Ingestion Flow (Extended)
```
POST /sbom/upload
  └─ parse components
  └─ aggregate vulnerabilities per component
  └─ update SbomVulnAggregate index
  └─ compute updated summary (exec_hash)
  └─ emit factor summary (store separately)
  └─ trigger optional recompute of decisions referencing exec_hash (future opt-in)
```

## Scoring Integration
Add new enrichment step `SBOMVulnMapper` invoked in deep path OR opportunistically post-baseline if exec hash present in event metadata. Produces `Enrichment {factors:[...], partial_confidence_delta: float, metadata:{sbom:{severity_counts, density, max_cvss}}}`.

## SSE Update Strategy
When SBOM ingestion changes factor set for a related artifact already streamed:
1. Produce `artifact_update` event containing diff: added/removed `sbom:*` factors and new cumulative delta.
2. Update UI trace panel to show supply chain influence timeline.

## Edge Cases
| Case | Handling |
|------|----------|
| Missing severity (none / unknown) | Count toward `unknown`; ignore for severity thresholds |
| Duplicate vulnerability entries | De-duplicate by (id, component) key |
| Large monolithic SBOM (>10k components) | Stream parse; cap per-cycle processing time; schedule continuation chunk |
| Rapid successive SBOM uploads (same exec_hash) | Debounce (e.g., 30s window) to prevent oscillation |
| CVSS versions (v2 vs v3) | Normalize to v3 base if mapping available else keep max numeric |

## Persistence (Optional Phase 1.5)
`data/sbom_vuln_aggregates.jsonl` append-only snapshots for restart resilience; load into memory at startup.

## Testing Plan
1. Unit: severity bucket aggregation correctness.
2. Unit: scaling function enforces +0.20 cap.
3. Unit: CWE cluster → MITRE technique factor injection (dedupe).
4. Replay: Synthetic SBOM sets verifying factor presence/absence boundaries.
5. Performance: 5k component SBOM processed within target (<500ms parse budget) on reference hardware.

## Metrics Additions
| Metric | Type | Labels | Purpose |
|--------|------|--------|---------|
| `sbom_ingest_total` | Counter | status | Track accepted vs failed uploads |
| `sbom_vuln_factors_total` | Counter | factor | Frequency of each sbom factor emitted |
| `sbom_density_ratio` | Gauge | exec_hash | Monitor density trend |
| `sbom_recompute_latency_ms` | Histogram | - | SBOM factor enrichment latency |

## Rollout Strategy
Phase 1 (Read-Only Influence): Add factors but keep cumulative SBOM cap at +0.10 (conservative). Log recommended vs applied scaled deltas for calibration analysis.
Phase 2 (Full Influence): Enable +0.20 cap once false positive impact assessed.
Phase 3 (Adaptive): Dynamic cap based on historical precision of SBOM-driven escalations.

## Security & Integrity Considerations
- Validate SBOM JSON against CycloneDX minimal schema subset to avoid ingestion abuse.
- Strip unexpected fields; size & component count guards (reject > configured max unless feature flag).
- Hash raw SBOM document; store hash alongside aggregates for provenance.

## Open Questions
1. Should stale vulnerability age factor (`sbom:vuln_age_stale`) decay if patching partial progress observed? (Option: age resets when count in bucket drops ≥ X%).
2. Introduce negative factors for demonstrably clean SBOM (e.g., `sbom:low_exposure`)? (Maybe; risk of overconfidence.)
3. Trigger retroactive decision updates or only apply to new artifacts? (Start forward-only to avoid noisy churn.)

---
Version: 0.1  
Status: Draft (ready for implementation alignment)
