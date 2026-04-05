# Additional Enhancements (Top 3)

## 1. Factor Category Tagging
Assign categories (e.g., `initial_access`, `lateral_movement`, `exfiltration`, `execution`) to each factor via an extended JSON mapping. 

Benefits / ROI:
- Enables category-level suppression / weighting (faster governance tuning).
- Improves analyst triage grouping in UI dashboards (reduces triage time ~5-10%).
- Facilitates category precision metrics (identify weak tactical areas quickly).

Effort: Low (extend `factor_descriptions.json` with `category` field + small loader change).
Risk: Minimal; purely additive metadata.

## 2. Lane Emission Sampling Toggle
Introduce optional sampling `pipeline.hunt_lanes.sampling_rate` (default 1.0) to limit persistence volume for very high-traffic tenants.

Benefits / ROI:
- Predictable storage growth control (cost containment for large customers).
- Maintains representative statistical sample for precision modeling.
- Avoids future migration to prune oversize tables.

Effort: Low/Medium (add simple random check before DB insert + metric adjustment for extrapolation).
Risk: Slight complexity in interpreting absolute emission counts (document scaling factor).

## 3. Correlation Rule Metrics & Hit Quality Tracking
Add per-rule counters + conditional precision tracker (TP/FP tallies through feedback integration) for correlation factors.

Benefits / ROI:
- Rapid identification of low-value rules for pruning (reduces noise & maintenance).
- Data-driven proposal for promoting correlation factors to scoring with justified precision.
- Supports auto-retirement threshold (e.g., rule disabled if conditional precision < 0.3 after N observations).

Effort: Medium (extend correlation engine, integrate with feedback tally, new Prometheus counters `hunt_correlation_rule_hits_total{rule}` and gauges for conditional precision).
Risk: Moderate if mis-labeled feedback; mitigated by requiring minimum observations before action.

---
Recommended execution order post-launch readiness: (1) Correlation Rule Metrics (to accelerate iteration), (2) Factor Category Tagging (analyst UX), (3) Lane Emission Sampling (cost scaling trigger-based).
