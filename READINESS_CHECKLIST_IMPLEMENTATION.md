# Readiness Implementation Snapshot (Incremental Build)

This document captures the concrete artifacts and modules added to advance the
early ingestion + false positive reduction roadmap.

## Canonical Schema & Mapping
- Model: `CanonicalEvent` in `src/api/schemas.py` (timestamp, source_type, ip_src, ip_dst, user, host, process, file_hash, domain, action, outcome, provenance).
- Mapping library extended: `src/core/mapping/canonical.py` (aliases + confidence scoring).
- Header inference helper: `src/core/mapping/header_inference.py` (suggestions with sample values & confidence).
- Provenance tagging: `src/core/mapping/provenance.py`.

## Factor Calibration
- Incremental weight adjustment via analyst feedback: `src/core/calibration/weights_calibrator.py` (bounded logistic-style updates to `risk_config.json`).

## Suppression Governance
- Admin endpoints: `src/api/suppression_admin_endpoints.py` for listing/adding templates (requires `ADMIN_API_KEY`).
- Existing engine integrates new templates on add (best-effort reload).

## Baseline & Anomaly (Pre-Existing)
- Baseline EWMA + z-score: `src/core/baseline_service.py` (leveraged for deviation detection).

## Metrics & Quality
- FP & mapping coverage metrics: `src/core/metrics/fp_quality.py` (precision events, suppression usage, mapping coverage ratio).

## Pending Next Steps (Not Yet Implemented Here)
1. Feedback endpoint expansion to accept TP/FP labels at decision-level and invoke `weights_calibrator.apply_vote` heuristics.
2. Temporal HopGraph edge enrichment (sequence metadata + path scoring).
3. RBAC roles & audit logging expansion for suppression changes (basic admin key today).
4. Performance baselines & SLO instrumentation (ingest latency, graph retrieval p95).
5. Scenario replay harness for precision/recall evaluation.
6. Suppression template test coverage & UI integration for analyst rule suggestion.

## Usage Notes
- Mapping coverage: compute `mapped=len(mapping)` vs `total=len(CANONICAL_FIELDS)` and call `record_mapping_coverage`.
- Weight calibration: integrate into factor feedback flow (vote=+1/-1) for factors impacting decisions.
- Provenance: attach adapter identifiers at ingestion for per-feed FP analytics.

## Security Considerations
- Suppression template modifications require `ADMIN_API_KEY`; future enhancement: role-based tokens & audit entries.
- Risk config updates restricted via existing admin endpoints; calibrator persists after bounded adjustments.

## Rollout Guidance
1. Enable header inference in multi-source upload page for mapping preview.
2. Capture decision-level TP/FP labels and emit `precision_events_total` metrics.
3. Start weekly reviews of top suppression template candidates derived from factor frequency + analyst votes.
4. Gradually increase factor weight learning rate only after stability (observe drift for two weeks).

---
This file will evolve as remaining roadmap items are implemented.