# Metrics Cardinality Guidance

This document summarizes current Prometheus metrics exposed by the platform and provides guidance to avoid excessive label cardinality.

> Keep time series count predictable and < O(10^4) per deployment. Favor fixed/low-cardinality label sets.

## Goals
- Keep time series count predictable and < O(10^4) for single-tenant dev/demo.
- Prevent unbounded growth via host/user/JA3/device identifiers directly in labels.
- Prefer aggregation at scrape time or pre-bucketing.

## Existing Metrics (Network Hunter)
| Metric | Type | Labels | Cardinality Notes |
|--------|------|--------|-------------------|
| networkhunter_factors_total | Counter | factor | Factor set bounded (<200). Safe. |
| network_hunter_novel_domains_total | Counter | (none) | Monotonic. |
| network_hunter_port_scatter_events_total | Counter | (none) | Low event rate. |
| network_hunter_portscan_vertical_total | Counter | (none) | Low signal only. |
| network_hunter_portscan_horizontal_total | Counter | (none) | Low signal only. |
| network_hunter_header_accept_rare_total | Counter | (none) | Bounded by rarity threshold. |
| network_hunter_header_accept_language_rare_total | Counter | (none) | Bounded by rarity threshold. |
| ssl_certs_analyzed_total | Counter | (none) | Volume-proportional; acceptable. |
| ssl_cert_self_signed_total | Counter | (none) | Low frequency. |
| ssl_cert_expired_total | Counter | (none) | Low frequency. |
| ssl_cert_short_validity_total | Counter | (none) | Low frequency. |
| ssl_cert_weak_signature_total | Counter | (none) | Low frequency. |
| ssl_cert_rare_issuer_total | Counter | (none) | Rare only. |
| networkhunter_stage_latency_seconds | Histogram | (none) | Default buckets; consider custom if p99 needed. |
| networkhunter_distinct_ja3_total | Gauge | (none) | Monotonic-ish; track for growth. |
| networkhunter_distinct_user_agents_total | Gauge | (none) | Might grow; alert if > few K. |
| network_active_beacon_keys | Gauge | (none) | Active (retained) beacon flow keys; alert if approaching memory cap. |

## Existing Metrics (Endpoint Hunter)
| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| endpoint_lineage_cache_size | Gauge | (none) | Track lineage map growth; alert if >50k entries. |
| endpoint_exec_burst_events_total | Counter | (none) | Bursty but bounded. |

## Existing Metrics (HopGraph)
| Metric | Type | Labels | Notes |
|--------|------|--------|-------|
| hopgraph_edges_total | Counter | (none) | Increment on edge add. |
| hopgraph_prune_total | Counter | (none) | Increment per prune cycle. |
| hopgraph_explain_total | Counter | (none) | Increment per explain invocation. |

## Patterns to Avoid
- DO NOT add per-host, per-user, per-IP labels directly (explodes cardinality).
- Avoid embedding raw JA3, domains, hashes, process names as labels; use counters with factor label already defined.
- Keep any new factor label sets enumerated and < 500 distinct values.
- Do not label metrics by arbitrary node identifiers (e.g., hopgraph node names) — use aggregate counters.
- Do not expose user/tenant IDs as labels; isolate via scrape target or relabeling if multi-tenant.

## Adding New Metrics Safely
## Environment Variables Impacting Metrics Behavior (No New Labels)
| Env Var | Effect |
|---------|--------|
| MULTISCALE_BEACON_ENABLED | Internal computation only; no label addition. |
| HOPGRAPH_EXPLAIN_CACHE_MAX | Cache sizing only. |
| BEACON_CONN_MAXLEN | Affects memory/time only. |
| BEACON_CONN_RETENTION_SECONDS | Affects pruning interval only. |
| LOLBIN_TFIDF_* | Alters emission frequency of bounded factor labels. |

## Future Work
- Add hopgraph_explain_cache_hit_total / miss_total (bounded outcome label) if needed.
- Gauge for active beacon flow keys (with upper bound alerting).

1. Ask: Can this be a counter with a bounded enum label instead of dynamic values?
2. If tracking distinct counts (e.g., unique JA3), prefer a gauge updated with len(map) rather than label explosion.
3. For high-cardinality debug visibility, use logs or on-demand endpoints instead of metrics.
4. Consider downsampling or summarizing (e.g., buckets for size ranges) rather than raw values as labels.

## Cardinality Budget (Guideline)
| Category | Target Max Series |
|----------|-------------------|
| Factors counters | 250 |
| Core gauges | 50 |
| Histograms (all buckets) | 200 |
| TOTAL (steady state) | < 1,000 |

## Alerting Suggestions
- Alert when distinct JA3 > 25k (possible memory pressure or unsampled environment).
- Alert when lineage_cache_size > 50k (consider pruning or TTL).
- Track rate of factor_counter for anomaly spikes (e.g., beacon_like surge).

## Future Enhancements
- Introduce a metrics registry wrapper that rejects new label values beyond a configured whitelist.
- Auto-prune large internal frequency maps (already done for Accept/Accept-Language).
