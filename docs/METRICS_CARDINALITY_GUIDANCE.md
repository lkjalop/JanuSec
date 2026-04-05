Metrics cardinality guidance (short)

This note covers best-practice guidance for the custom counters and gauges added by the hunters.

Key points
- Avoid high-cardinality label values. Labels should be low-cardinality enums (factor names, source names, outcome) not freeform strings (IP addresses, hostnames, user agents).
- If you need per-entity metrics (e.g., per-tenant), consider a separate aggregated metric export or a multi-tenant label limited to <100 distinct values.
- Counters added by the hunters use labels like `factor`, `source`, `type`, and `outcome`. Keep these stable and documented.
- For debugging, use histograms/gauges sparingly and prefer summations/rollups in Prometheus queries rather than per-entity labeling.

Operational advice
- Set up alerting on metric cardinality growth (e.g., number of unique `factor` labels or unique time series per metric).
- Periodically review label values via the Prometheus UI and prune any labels created by misconfigured services.

Files and metrics to watch
- `networkhunter_factors_total{factor=...}` — factor label cardinality should be bounded to the set of supported factors in the code.
- `intel_ioc_confidence_distribution` — histogram; avoid adding labels per indicator.

If you'd like, I can add a lightweight script that scans the codebase for metric registrations and emits a list of labels used (helps ensure labels are static and under control).