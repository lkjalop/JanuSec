ndpoint & Transport
- Route: `GET /api/v1/graph/session/stream`.
- Implementation: `src/api/hopgraph_stream.py`.
- Transport: Server-Sent Events over HTTPS (FastAPI `StreamingResponse`).
- Client helper: `frontend/static/js/hopgraph_stream_overlay.js` (LIVE console and HopGraph Lite auto-connect).

### Authentication & Tenant Scoping
- The route reuses the platform `require_api_key` dependency. Only API keys defined in `API_KEYS_JSON` (or JWTs) can connect.
- Optional tenant filter via `X-Tenant-ID`. When `HOPGRAPH_STREAM_REQUIRE_TENANT=1`, connections must provide the tenant header.
- Each client queue stores the tenant scope; events are only forwarded if the overlay’s tenant matches the client filter.
- Default demos (single tenant) omit the header, but prod deployments should set `HOPGRAPH_STREAM_REQUIRE_TENANT=1`.

### Event Payload
- Publisher: `publish_hopgraph_overlay` invoked from `graph_sessions.build_session` once the summary is persisted.
- Event includes: session_id, tenant, verdict, confidence, diversity/mapping scores, kill-chain & ATLAS tags, trimmed factor metadata, graph counts, and the latest `hopgraph_overlay` snapshot (supply-chain/binary/infrastructure nodes).
- Events are cached in a ring buffer (`HOPGRAPH_STREAM_BACKLOG`, default 40) so new listeners receive recent overlays immediately.

### Backpressure & Metrics
- Async queues (per client) prevent pipeline blocking; failed clients are ignored.
- Prometheus metrics: `hopgraph_stream_events_total`, `hopgraph_stream_clients`, `hopgraph_stream_queue_depth`.
- Keepalive comments are emitted every 10s to keep proxies alive.

### Security Checklist
1. **Auth** – API key/JWT enforced at connection time. No anonymous streaming.
2. **Tenant Isolation** – Header-based scoping plus optional enforcement env flag.
3. **Data Minimization** – Factors truncated (12 max), metadata trimmed to fields analysts need.
4. **Observability** – Metrics expose client count & queue depth for SRE alerting.
5. **Reconnection Safety** – Cached backlog prevents replay of stale data from other tenants.
6. **Config Hardeners** – `HOPGRAPH_STREAM_REQUIRE_TENANT`, `HOPGRAPH_STREAM_BACKLOG`, `HOPGRAPH_STREAM_TEST_MODE` for CI.

### Frontend Usage
- LIVE console panel displays stream status, latest overlay summary, and quick actions.
- HopGraph Lite page consumes the same feed to animate nodes/edges when a preset session updates.
- UI fetch helper sends API key + tenant headers with `fetch` (custom SSE reader) to avoid leaking keys via query params.

### Operational Verification
1. Start backend with `API_KEYS_JSON` set. Optional: `HOPGRAPH_STREAM_REQUIRE_TENANT=1`.
2. Open LIVE console → confirm “HopGraph Stream” panel enters “connected” state.
3. Trigger `/api/v1/graph/session/build` (e.g., CSV analyzer “Send to HopGraph”) – panel log should show the new session and overlay nodes.
4. Inspect `/metrics` to see `hopgraph_stream_events_total` increment.
5. For multi-tenant tests, set different `X-Tenant-ID` headers and confirm cross-tenant events do **not** appear.

This document should accompany any future modification to the overlay feed (e.g., switching to WebSockets) to keep the security reasoning explicit.

### Multi-Domain Chains – Admin Controls
- **Config endpoints:** `GET /api/v1/correlation/multi-domain/config` returns the current `SESSION_TTL_SECONDS`, cleanup interval, and next scheduled sweep. `POST /api/v1/correlation/multi-domain/config` (admin key required) updates either/both values at runtime, so SREs don’t have to bounce the service to tune demo data retention.
- **Dashboard wiring:** The LIVE console “Multi-Domain Health” card now exposes the config form next to the TTL/queue banner. Successful updates call the POST endpoint above and immediately refresh the stats panel so operators see the new values + dependency warnings in one place.
- **Incident surfacing:** Aggregated incidents inherit HopGraph context (TTL, narratives, recommendation catalog) from multi-domain chains and display them in the LIVE console/SBOM cards. SOC analysts no longer need to pivot back into CSV tooling to read the recommendation catalog the roadmap mandates.

### Factor Synthesis Calibration Workflow
1. **Persist long-horizon priors** – `FactorQualityManager` now tracks an exponential-decay history per factor. Hit `/api/v1/admin/factors/telemetry` to confirm the `factor_history` block (tp/fp counts + age) before adjusting weights.
2. **Tune context multipliers** – Call `/api/v1/admin/factors/context` with entries such as `severity:critical=1.2` or `user_role:privileged=1.1`. The LIVE console Factor Telemetry pane refreshes automatically so ops can validate overrides.
3. **Regression pass** – Run `python -m pytest tests/test_factor_quality_history.py tests/test_risk_score_factor_synthesis_integration.py` to exercise Bayesian combination, decay, FP suppression, and synergy logic against the roadmap fixtures.
4. **Console validation** – Reload the Multi-Domain Health / Factor Telemetry cards (or SBOM correlation catalog) to see the updated priors, then trigger a sample decision to ensure Tier 1/Tier 2 LLM summaries display the refreshed Factor Synthesis insight.
