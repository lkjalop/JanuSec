# Operations & Production Runbook

This document lists important environment variables, runtime knobs, and operational steps for running the platform in production.

Required / Recommended Env Vars
- `ADMIN_API_KEY`: API key for admin endpoints (must be strong and rotated)
- `DEFAULT_FRONTEND`: `console` or other frontend selection
- `SESSION_PERSIST_DIR`: directory to persist correlation sessions (default `data/sessions`)
- `SESSION_TTL_SECONDS`: TTL for saved sessions (default 604800)
- `SESSION_CLEAN_INTERVAL_SECONDS`: background cleanup loop interval (0 to disable)
- `EWMA_HISTORY_PATH`: path to EWMA history file
- `EWMA_HISTORY_TTL_SECONDS`: prune horizon for EWMA history
- `ADAPTIVE_EWMA`: enable adaptive alpha derivation (0/1)
- `ADAPTIVE_EWMA_BASE_ALPHA`: base alpha for adaptive EWMA (0.0-1.0)
- `ADAPTIVE_EWMA_MIN_ALPHA`, `ADAPTIVE_EWMA_MAX_ALPHA`, `ADAPTIVE_EWMA_VOL_SCALE`: adaptive tuning knobs
- `SCORING_WEIGHTS_JSON`: JSON string overrides for scoring weights

Operational Playbook
- Boot: ensure `ADMIN_API_KEY` is set and secrets secured. Start the API with the chosen `DEFAULT_FRONTEND`.
- Health: monitor `/metrics` and `/api/v1/dashboard/status`.
- Sessions: ensure `SESSION_PERSIST_DIR` is writable and monitor disk usage; configure `SESSION_CLEAN_INTERVAL_SECONDS` to prune expired sessions.
- EWMA: backup `EWMA_HISTORY_PATH` regularly and monitor `EWMA_HISTORY_TTL_SECONDS` pruning activity.
- CI: ensure `scripts/run_rule_quality_sweep.py` and `scripts/compare_pack_to_sweep.py` run in pipeline to gate domain packs.

Incident Response
- If a high-confidence rule triggers, use the `decisions` endpoints to retrieve the `correlation_emission` evidence and escalate using playbooks in `src/soar`.
- For suspicious session files, move them to a quarantine directory and set `SESSION_TTL_SECONDS` to a low value while investigating.

Security
- Protect admin endpoints with `x-api-key` (header). Limit IP ranges and enable authentication at network layer.
- Rotate `ADMIN_API_KEY` regularly and store in a secrets manager.

Maintenance
- Run `python scripts/run_rule_quality_sweep.py` periodically to detect regressions or missing vectors.
- Keep `data/custom_test_vectors.json` in sync with `data/domain_pack_rules.json` to prevent pack gating failures.
# Operations & Observability Guide

## Threat Intelligence Layer

Endpoint: `GET /api/v1/intel/status`
Provides:
- `enabled`: feature flag state
- `counts`: current IoC object counts (ips, domains, urls, hashes, ja3, certfps)
- `last_sync`: epoch seconds per source
- `freshness_seconds`: age since last sync
- `stale`: boolean per source (age > 2× sync interval)
- `confidence_stats`: number of IoCs with aggregated confidence per kind
- `sync_interval`: configured periodic sync cadence

### Sources & Default Weights
| Source          | Weight | Default TTL Examples |
|-----------------|--------|----------------------|
| misp            | 1.0    | ip/domain 24h, hash 72h |
| opencti         | 1.0    | ja3 168h |
| abusech_sslbl   | 0.9    | ja3 336h |
| malwarebazaar   | 0.9    | hash 720h, url 168h |
| otx             | 0.7    | ip/domain/url 168h, hash 720h |
| curated         | 1.0    | ja3/ja4/certfp 720h |

Weighted confidence: `conf = min(1.0, (sum(weights)/count_sources) * 0.85)` (conservative cap).

Environment flags:
```
THREAT_INTEL_ENABLED=1
MISP_API_URL=...   MISP_API_KEY=...
OPENCTI_API_URL=... OPENCTI_API_KEY=...
OTX_API_KEY=...
THREAT_INTEL_SYNC_INTERVAL=900
TI_TTL_abusech_sslbl_ja3=720   # Example override
ALLOWLIST_JA3=ja3a,ja3b
ALLOWLIST_CERTFP=fp1,fp2
THREAT_INTEL_DB_ENABLED=0
```
Optional dependencies (install with extras):
```
pip install .[threat_intel]
```

## Baseline Intel Hit Rate Metrics
Exports (Prometheus):
- `baseline_events_total`
- `baseline_intel_match_total`
- `baseline_intel_match_ratio` (matched/total)

Interpretation: rising ratio post feed enable indicates feed IoCs contributing to early-stage suppression or triage.

## Certificate Analysis Metrics
Added in network hunter:
- `ssl_certs_analyzed_total` (incremented when cert context processed)
- `ssl_cert_self_signed_total`
- `ssl_cert_expired_total`
- `ssl_cert_short_validity_total`
- `ssl_cert_weak_signature_total`
- `ssl_cert_rare_issuer_total`

Factors Emitted (examples):
| Factor | Meaning | Typical Delta |
|--------|---------|---------------|
| ssl:self_signed_cert | Self-signed end-entity certificate | +0.08 |
| ssl:expired_cert | Certificate validity end < now | +0.07 |
| ssl:short_validity | Validity window < 30 days | +0.04 |
| ssl:weak_sig_algo | md5 / sha1 signature algorithms | +0.04 |
| ssl:rare_issuer | Issuer frequency <5 occurrences | +0.03 |
| ssl:invalid_chain | Chain validation failed | +0.05 |
| ssl:sni_mismatch | SNI vs Subject CN mismatch | +0.03 |

Use case: Track prevalence of ephemeral C2 infrastructure (short validity, self-signed) and aging infrastructure (expired cert spikes).

## Intel Confidence Introspection
Methods (internal):
- `ThreatIntelClient.ioc_confidence(kind, value)` → float | None
- `ThreatIntelClient.origin_for(value)` → last origin tag

Expose via future endpoint if needed to support UI factor drilling.

## Frontend Panel (Intel Status)
Static page: `/static/intel_status.html`
Displays counts, per-source freshness, and confidence coverage. Auto-refresh 60s.

## Deprecation Notice
`modules.threat_intel_cache.ThreatIntelCache` is deprecated; use `integrations.threat_intel_client.CLIENT` for new development. The legacy cache delegates `match_ioc` to the new client when available.

## Alerting Suggestions
Consider attaching alert rules (PromQL):
```
ALERT IntelSourceStale
  IF max_over_time(intel_sync_age_seconds[5m]) > (2 * THREAT_INTEL_SYNC_INTERVAL)
  FOR 10m
  LABELS { severity="warning" }
  ANNOTATIONS { summary="Threat intel source stale" }

ALERT HighSelfSignedRate
  IF increase(ssl_cert_self_signed_total[1h]) > 200
  LABELS { severity="medium" }
  ANNOTATIONS { summary="Spike in self-signed certs (possible C2 infra proliferation)" }
```
(Export `intel_sync_age_seconds` if adding a direct gauge; current implementation derives in API.)

## Future Enhancements
- Persist per-IoC confidence distribution to DB for historical decay modeling.
- Add gauge: `intel_sources_stale_total`.
- Add histogram: `intel_sync_latency_seconds` per source (already scaffolded as sync latency histogram if registry available).

## Troubleshooting
| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `/api/v1/intel/status` returns disabled | Feature flag off | Set `THREAT_INTEL_ENABLED=1` |
| No MISP attributes ingested | Missing dependency or invalid key | Install extras, verify API key/URL |
| Cert factors not appearing | Events missing `cert_*` fields | Ensure Zeek SSL log parser populates fields |
| High stale flags | Network / auth failures | Inspect logs for sync failures (`_SYNC_COUNTER` increments failure) |

---
Maintained by Security Engineering. Update when adding new sources or factor classes.

## Correlation & HopGraph Additions (Latest Sprint)

Environment flags:
```
# Enforce (default) or temporarily allow legacy temporal cache fallback
CORRELATION_TEMPORAL_PUBLIC_FALLBACK=0   # set to 1/true to allow legacy public namespace lookup; logs deprecation warning

# HopGraph explain search safety caps (0 disables)
HOPGRAPH_EXPLAIN_MAX_EXPANSIONS=0        # max edge expansions during explain_chain
HOPGRAPH_EXPLAIN_MAX_VISITED_EDGES=0     # alternative cap based on visited edges length per path
```

New Prometheus metrics:
- `janusec_correlation_temporal_cache_hits_total{tenant="..."}`
- `janusec_correlation_temporal_cache_misses_total{tenant="..."}`
- `janusec_correlation_temporal_cache_legacy_fallback_total{tenant="..."}` (only increments if fallback env flag enabled)
- `janusec_hunt_correlation_latency_seconds{had_event="0|1"}` – end-to-end correlate() latency
- `janusec_hopgraph_explain_chain_latency_seconds{start="node"}` – explain_chain timing

Operational guidance:
- Keep `CORRELATION_TEMPORAL_PUBLIC_FALLBACK` disabled in production; enable only for short migration windows if legacy public keys must be read, then turn off to guarantee strict tenant isolation.
- Watch legacy fallback counter; any non-zero increase after migration is a signal to disable the flag.
- Use expansion caps if pathological or adversarial graphs cause large explain latencies; start with `HOPGRAPH_EXPLAIN_MAX_EXPANSIONS=5000` and tune.

Alert suggestions:
```
ALERT CorrelationLatencyHigh
  IF histogram_quantile(0.95, rate(janusec_hunt_correlation_latency_seconds_bucket[5m])) > 0.5
  FOR 10m
  LABELS { severity="warning" }
  ANNOTATIONS { summary="Correlation latency p95 > 500ms" }

ALERT HopGraphExplainSpikes
  IF histogram_quantile(0.95, rate(janusec_hopgraph_explain_chain_latency_seconds_bucket[5m])) > 1.0
  FOR 10m
  LABELS { severity="medium" }
  ANNOTATIONS { summary="HopGraph explain p95 > 1s – consider lowering expansion caps" }
```

Deprecation notice:
- The legacy temporal cache public namespace fallback is deprecated and will be removed after migration; relying on it emits a log warning and increments the fallback counter.
