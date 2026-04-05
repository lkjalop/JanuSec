# Runtime & Integration Notes

## Dependencies

| Purpose | Library | Reason |
|---------|---------|--------|
| Excel ingestion | `openpyxl` | Parse `.xlsx` sheets in streaming (read_only) mode |
| PDF reports | `reportlab` | Generate PDF ingestion reports |
| Optional PDF parsing in tests | `pdfplumber` | Validate PDF size/structure (optional) |

Install (example):

```
pip install openpyxl reportlab pdfplumber
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SSE_TEST_MODE` | unset | If set (any value) first SSE connection yields one `test-mode` event then closes (simplifies tests). |
| `ALLOWED_ORIGINS` | `https://localhost` | CORS allow-list for browser UI. Add your frontend origin if different. |
| `ZEEK_NXDOMAIN_RATE_THRESHOLD` | `0.35` | NXDOMAIN ratio threshold used in DNS anomaly tracking. |
| `NX_RATE_TRACKER_ENABLED` | `1` | Disable with `0` to turn off NX tracking. |
| `ALERT_DEDUP_TTL_SECONDS` | `30` | Dedup window for alert emission in seconds. |
| `MEMORY_SANDBOX_ADAPTERS` | `local` | Comma-separated adapters (`local,joe,anyrun,cuckoo`) that receive memory artefacts; non-local entries require matching API endpoints/tokens. |
| `JOE_API_ENDPOINT` / `JOE_API_TOKEN` | unset | Configure when `joe` is listed in `MEMORY_SANDBOX_ADAPTERS` to forward dumps to Joe Sandbox. |
| `ANYRUN_API_ENDPOINT` / `ANYRUN_API_TOKEN` | unset | HTTP endpoint + token for AnyRun submissions. |
| `CUCKOO_API_ENDPOINT` / `CUCKOO_API_TOKEN` | unset | HTTP endpoint + token for a Cuckoo cluster. |

## Memory Forensics Ops (Proof + Courier Harness)

1. **Managed-HSM proof** – ensure the attestor can reach your KMS/HSM (e.g., set `MEMORY_HSM_BACKEND=azure` + vault/key vars), then run:
   ```
   PYTHONPATH=. python tools/run_hsm_proof.py --tenant <tenant-id> --simulate-tamper
   ```
   This captures `/api/v1/forensics/memory/hsm_health` output, tamper telemetry, and `hsm_alerts.log` under `logs/perf/api_stage/artifacts/memory/hsm/<tenant>/` so ULTRADEEP & the LIVE console can deep-link to the evidence bundle.

2. **Courier SLA soak** – iterate every tenant definition (usually `config/api_stage_tenants.ci.json`) and emit per-attestation artefacts + a manifest:
   ```
   PYTHONPATH=. python tools/run_courier_soak.py --tenants config/api_stage_tenants.ci.json
   ```
   The script writes JSON snapshots to `logs/perf/api_stage/artifacts/courier/` and a `courier_manifest.json` summarising TTL/SLA state for the LIVE console “Courier & Attestation” panel.

3. **Real sandbox parity** – set `MEMORY_SANDBOX_ADAPTERS=joe,anyrun` (and matching `*_API_ENDPOINT`/`*_API_TOKEN` values) so production runs forward artefacts to your Joe/AnyRun deployments while the new CI tests keep the adapters honest.

4. **Rekall/Sandbox health** – capture parity metrics with:
   ```
   PYTHONPATH=. python tools/run_memory_health.py --fixture-dir tests/fixtures/memory/health
   ```
   This produces `logs/perf/api_stage/artifacts/memory/health/manifest.json` detailing Volatility vs Rekall plugin coverage and sandbox adapter status.

5. **Timeline publication** – drop anonymised multi-platform timelines for ULTRADEEP reviewers:
   ```
   PYTHONPATH=. python tools/publish_memory_timelines.py --fixture-dir tests/fixtures/memory/health
   ```
   Outputs appear under `logs/perf/api_stage/artifacts/memory/timelines/` and can be linked from ULTRADEEP + the LIVE console evidence panes.

## SSE Streaming
Decisions are published to `/api/v1/stream/decisions` via `_record_decision` which both updates `DECISION_CACHE` and schedules an async publish. Frontend reconnection uses exponential backoff.

## Upload Alias
`POST /api/v1/upload/tabular` maps to the multi-file handler so the React UI can uniformly post CSV + Excel. Excel requires `openpyxl` installed; otherwise an actionable error is returned.

## Security Hardening (XDR / Webhook Integrations)
Implemented features:
1. **Inbound Authentication** – HMAC-SHA256 over `timestamp.raw_body` with rotating secrets (register & rotate endpoints). Multiple secrets honored during grace window.
2. **Replay Protection** – Timestamp + signature replay set with timestamp pruning within skew window.
3. **Per-Integrator Rate Limiting** – Token bucket (capacity & refill configurable).
4. **Payload Size Validation** – Enforced max body (`XDR_WEBHOOK_MAX_BYTES`).
5. **Async Isolation** – Events enqueued and processed by background worker; classification/rule evaluation performed if rule engine present.
6. **Audit Hash Chain** – JSONL per integrator with `prev_hash` + `hash`, verification script `scripts/verify_xdr_audit_chain.py`.
7. **Secret Rotation** – `/api/v1/integrations/xdr/rotate` sets grace period for old secret (`XDR_SECRET_GRACE_SECONDS`).
8. **Error Obfuscation** – Optional (`XDR_OBFUSCATE_ERRORS=1`) to collapse sensitive errors to uniform 401.
9. **Challenge Verification** – `/api/v1/integrations/xdr/verify` HMAC challenge-response.

## Proposed XDR Integration Contract (Draft)
```
POST /api/v1/integrations/xdr/webhook
Headers:
  X-Integrator-ID: <id>
  X-Signature: sha256=<hex HMAC>
  X-Timestamp: <unix seconds>
Body: { "events": [ {"id":"...","type":"process","host":"...",...} ] }
```
Server steps:
1. Validate required headers present.
2. Check absolute skew |now - X-Timestamp| < 300.
3. Compute HMAC over raw body with shared secret for integrator id.
4. Replay check `(integrator_id, timestamp, hmac)` tuple.
5. Enqueue each event for normalization (do not inline classify if high volume).
6. Respond 202 with accepted count.

## Additional Hardening Roadmap
- Pluggable secret backend (Vault / KMS) instead of in-memory/env.
- Daily audit log rotation & compression.
- Circuit breaker for downstream enrichment calls (future).
- Structured metrics export (rate limit hits, replay rejects, rotation count).

## Frontend Accessibility
Recent pass added aria labels, roles, keyboard handlers on navigation, toolbar controls, and grid rows.

## Incident & Override
Endpoints added:
- `POST /api/v1/incidents`
- `GET /api/v1/incidents`
- `PATCH /api/v1/decisions/{event_id}/override`

### Kill-switch & Dry-run

### Feature Flags & Canary

Use env-driven feature flags for safe rollout and quick rollback:

- FEATURE_SLO_ENFORCE_DISPLAY: Enable stricter SLO display/annotations (default off)
- SLO_EWMA_ALPHA: Tuning for EWMA smoothing (default 0.3)
- RL_CANARY_ENABLED: Use canary rate-limit capacity/refill values
  - RL_CANARY_CAPACITY, RL_CANARY_REFILL
- Circuit breakers (best-effort stubs):
  - CB_ENABLED (or CB_SLACK_ENABLED / CB_ECLIPSE_ENABLED)
  - CB_FAIL_THRESHOLD (default 3), CB_RESET_SECONDS (default 30), CB_HALF_OPEN_TRIALS (default 1)
- OUTBOX_ENABLED: Reserved for enabling outbox-based delivery

Canary guidance:
- Start with a single tenant or connector; set RL_CANARY_ENABLED=1 and smaller capacity.
- Monitor guardrail metrics on the Grafana dashboard; adjust gradually.
- Rollback by unsetting the flags or reverting the canary capacity/refill.

SLO Alerting (PromQL examples):
- Success rate too low over 5m window:
  - avg_over_time(janusec_slo_success_rate[5m]) < 0.95
- 5xx error rate too high over 5m window:
  - avg_over_time(janusec_slo_errors_5xx_rate[5m]) > 0.05

Follow-up: wire these actions to frontend buttons (currently visual only).

---
Updated: 2025-09-30 (advanced XDR security)

## Operator Guide: Compliance & Posture

- Upload CSPM findings to `/api/v1/compliance/posture` with body `{findings:[{id,type,resource,severity}], tenant_id}`.
- Summarize cloud/K8s/IAM posture per tenant: `GET /api/v1/compliance/posture`.
- Generate executive ingestion report: `/api/v1/report/ingestion?format=html&include_model=true` (includes mapped control IDs: CIS/NIST/ISO).

Headers: include `x-api-key` (local default `devkey123`) and `X-Tenant-ID` for tenant scoping.

Security: terminate TLS at the gateway/ingress; prefer OAuth2/OIDC or mTLS (see deploy/gateway). Redaction and webhook guardrails are enabled in `src/core/redaction.py` and `src/api/webhook_middleware.py`.

## How To Validate (Quick)

- SSRF blocking (egress safety):
  - Set `SLACK_WEBHOOK_URL=http://127.0.0.1:9999/hook` and POST `{"service":"slack"}` to `/api/v1/webhooks/dispatch` → expect 400 with `detail: ssrf_blocked:*`.
- Content-Type guard:
  - POST non-JSON to `/api/v1/integrations/slack/config` (e.g., `Content-Type: text/plain`) → expect 400 `bad_json` (or 415 if enforced by gateway).
- HMAC/replay (webhooks):
  - Missing or stale `X-Timestamp`/`X-Signature` on `/api/v1/webhooks/*` → expect 401/409 per `src/api/webhook_middleware.py`.
- Upload truncation:
  - Oversized CSV/JSON to `/api/v1/upload/files` with `MAX_CSV_ROWS`/`MAX_JSON_RECORDS` set → response `analysis.truncated == true`.
- Archive caps:
  - ZIP with many CSV members; set `MAX_ARCHIVE_MEMBERS=1` → response `member_summaries` includes `skipped: limits_exceeded`.

## Edge/Gateway Examples

- NGINX (TLS 1.3, CSP, rate limits): see `deploy/gateway/nginx_security_examples.conf`.
- Kong (rate limiting + header transforms): see `deploy/gateway/kong_policies.yaml`.

## Alerts (Prometheus)

- Guardrail alert rules: `monitoring/alert_rules_guardrails.yml` (SSRF blocks, rate-limit drops, upload errors).

## Risk Scoring (Stage 3 Core)
Endpoints:
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/risk/score` | Submit an ad-hoc decision-like object and receive risk composition. |
| GET | `/api/v1/risk/score/{event_id}` | Compute risk for a cached decision (in-memory `DECISION_CACHE`). |

POST Request Body:
```
{ "decision": { "event_id": "evt-1", "factors": ["scenario:critical_exec","net:suspicious"], "confidence": 0.9 } }
```

Response (fields subset):
```
{
  "score": 0.87,
  "raw_score": 0.65,
  "breakdown": [
    {"factor":"scenario:critical_exec","weight":0.95,"contribution":0.95,"source":"factor"},
    {"factor":"net:suspicious","weight":0.6,"contribution":0.6,"source":"factor"}
  ],
  "method": "multiplicative",
  "variance": 0.012,
  "ci95": [0.70, 0.92]
}
```

Composition Highlights:
- Factors fused via multiplicative complement: `combined = 1 - Π(1 - c_i)` with penalties applied as shrink multipliers.
- Optional sigmoid calibration (`RISK_SIGMOID_CALIBRATION=1`) using `RISK_SIGMOID_K` & `RISK_SIGMOID_X0`.
- High-risk tagging when `score >= RISK_HIGH_THRESHOLD` adds `risk:high` meta factor.
- Cluster novelty (`cluster:novelty`) and geo velocity anomaly (`geo:velocity_improbable`) auto‑added if present.
- Completeness penalty: if required factor classes missing (see env `RISK_COMPLETENESS_*`).

Prometheus Metrics:
- Internal dynamic histogram via `core.metrics.registry` (tenant-labeled) plus global histogram `risk_score_distribution` when Prometheus metrics are enabled.

Key Environment Variables:
| Variable | Purpose |
|----------|---------|
| `RISK_FACTOR_WEIGHTS` | Comma list `factor=weight` explicit overrides. |
| `RISK_FACTOR_WEIGHTS_<TENANT>` | Tenant-specific overrides. |
| `RISK_WEIGHTS_YAML` | Path to YAML with `{factor: weight}` for hot reload. |
| `RISK_HIGH_THRESHOLD` | Score threshold for `risk:high` tagging. |
| `RISK_COMPLETENESS_EXPECTED_CLASSES` | CSV of required factor class prefixes. |
| `RISK_COMPLETENESS_MIN_PRESENT` | Min distinct classes to avoid penalty. |
| `RISK_COMPLETENESS_PENALTY` | Penalty magnitude (0-1). |
| `RISK_SIGMOID_CALIBRATION` | Enable sigmoid calibration if set. |

### Kill-switch & Dry-run

Environment flags to safely disable outgoing side effects or run in dry-run mode:

- Global dry-run: `DRY_RUN=1` (prevents Slack/Eclipse dispatch)
- Per-tenant dry-run: `DRY_RUN_TENANTS="tenantA,tenantB"`
- Connector kill-switches:
  - `DISPATCH_DISABLE_SLACK=1`
  - `DISPATCH_DISABLE_ECLIPSE=1`
  - Per-tenant: `DISPATCH_DISABLE_SLACK_TENANTS`, `DISPATCH_DISABLE_ECLIPSE_TENANTS`
- Optional approval stub: `DISPATCH_REQUIRE_MFA=1` (placeholder hook for integrating MFA/approvals)

Notes:
- Dry-run also respects legacy `DISPATCH_DRY_RUN=1`.
- All flags are evaluated per dispatch; per-tenant lists are comma-separated.
Testing:
- `tests/test_risk_score_endpoint.py` covers POST, GET, empty decision, and edge cases.
- `tests/test_risk_enhancements.py` exercises integration of risk attributes on decisions.

Extension Ideas:
- Add priors or Bayesian update based on historical false positive rate.
- Incorporate temporal decay per factor class.
- Persist learned weights (currently in-memory) via simple SQLite or Redis backend.


## Network Hunter MVP
Implemented lightweight network tradecraft analysis gated by `NETWORK_HUNTER_ENABLED` (default on):

Factors emitted (cumulative confidence capped at 0.15):
- `ssl:ja3_known_bad` – JA3 hash in small curated malicious fingerprint set.
- `ssl:ja3_rare` – JA3 observed <5 times (rarity heuristic).
- `dns:long_label` – Any DNS label length >30 characters.
- `dns:tunnel_suspected` – High-entropy concatenated subdomain (entropy >3.3) AND >=30 queries in 60s window to same SLD.
- `net:beacon_periodic` – Connection tuple (src,dst,port) with >=8 intervals over ≥10m and coefficient of variation <0.20.
- `http:user_agent_rare` – User-Agent seen fewer than 3 times.

Metrics (Prometheus):
- `networkhunter_factors_total{factor}` – per-factor counts.
- `networkhunter_stage_latency_seconds` – analysis latency histogram.
- `networkhunter_distinct_ja3_total` / `networkhunter_distinct_user_agents_total` – cardinality gauges.

Environment Variables:
| Variable | Default | Description |
|----------|---------|-------------|
| `NETWORK_HUNTER_ENABLED` | `true` | Set to `false`/`0` to disable stage rapidly. |

Roadmap Additions (future): certificate anomalies (`ssl:self_signed_cert`, `ssl:expired_cert`), port scan heuristic, expanded JA3 known-bad corpus, DNS DGA detection.
