# Coding Agents Guide (Copilot, Claude Code, etc.)

This repository contains multiple frontends. The canonical, demo-ready UI is the static "LIVE Console". Follow these instructions to avoid breaking the UI or wiring the wrong pages.

## Canonical Frontend

- Use `frontend/static/janusec-platform-complete-LIVE.html` as the primary console UI.
- It is served by the API at the root ("/") when `DEFAULT_FRONTEND=console`.
  - See `src/api/app.py` (routes `serve_root`, `serve_console`, `serve_live`) which reference `janusec-platform-complete-LIVE.html` under `/static`.
- Do NOT move or replace the LIVE console with other templates. Extend it by adding additional static pages under `frontend/static/` and linking from the left sidebar.

## Added Static Pages

- Network Hunt: `frontend/static/hunt_network.html`
- Endpoint Hunt: `frontend/static/hunt_endpoint.html`
- Metrics: `frontend/static/metrics.html`
- Integrations Settings: `frontend/static/integrations.html`
- SBOM & Vulnerabilities: `frontend/static/sbom.html`
 - Multi-Log Investigator: `frontend/static/multi_log_investigator.html` — submit suspicion-driven requests, view correlation summary, ranked evidence, next-best suggestions, capture actions, and adjust scoring guardrails.

These pages are intentionally framework-free and use the same dark theme variables as the LIVE console.

## Key UI Anchors in LIVE Console

- File: `frontend/static/janusec-platform-complete-LIVE.html`
  - Right-panel actions are bound via explicit handlers:
    - `createIncidentFromRecent()` – creates an incident using `/api/v1/incidents`.
    - `exportInvestigationReport()` – opens `/api/v1/report/ingestion?format=html&include_model=true&include_scenarios=true`.
    - `sendToSiem()` – demo dispatch via webhook test (toast confirmation).
  - Upload drop-zone toggled by the "Upload Logs" button.
  - Navigation items link to the static pages above (Network/Endpoint/Metrics/Integrations/SBOM).

## Required Headers / Auth

- Many API routes require an API key header: `x-api-key`.
- The static pages set it from `localStorage.apiKey` or default to `devkey123`.
- Ensure calls include headers, e.g. `{'x-api-key': 'devkey123'}` (for local/dev).

## Backend Endpoints (used by the UI)

- Dashboard/metrics/status
  - `GET /api/v1/dashboard/status`
  - `GET /api/v1/dashboard/metrics`
  - `GET /api/v1/status/dashboard`
  - `GET /api/v1/finops/*` (overview, cost_summary, history)
- Decisions / explain / incidents
  - `GET /api/v1/decisions/recent`
  - `GET /api/v1/decisions/{event_id}/explain`
  - `POST /api/v1/incidents`
- Uploads
  - `POST /api/v1/upload/files`
 - On-Demand Fetchers (lightweight demo stubs)
   - `POST /api/v1/fetch/lines` — parse Zeek/JSONL lines into a session envelope
   - `POST /api/v1/fetch/zeek|suricata|sysmon|etw` — synthetic normalized sessions honoring filters/time-window
 - Capture stubs
   - `POST /api/v1/capture/pcap/start` — pending approval record, returns expected costs/privacy
   - `POST /api/v1/capture/ebpf/start` — pending approval record with profile, costs/privacy
- Integrations
  - `POST /api/v1/integrations/{name}/toggle?enabled=...`
  - `POST /api/v1/webhooks/test` (body `{service:'slack'|'teams'|'whatsapp'}`)
  - `POST /api/v1/integrations/{name}/config` (body `{webhook_url: '...'}`) [added]
- SBOM (lightweight demo mapping)
  - `POST /api/v1/sbom/upload` (body `{components:[{name,version,...}]}`)
  - `GET /api/v1/sbom/vulns?sbom_id=...`
- Prometheus
  - `GET /metrics`

## Serving the LIVE Console

- The API file `src/api/app.py` contains references to the LIVE console:
  - It attempts to serve `frontend/static/janusec-platform-complete-LIVE.html` at `/`, `/console`, and `/live` depending on `DEFAULT_FRONTEND`.
- The Windows starter sets `DEFAULT_FRONTEND=console`.
  - File: `start_server.bat` (environment section).

## Do / Don’t

- Do: add new static pages under `frontend/static/` and add sidebar links in `janusec-platform-complete-LIVE.html`.
- Do: use the listed API endpoints; send `x-api-key`.
 - Do: prefer `/api/v1/admin/scoring/weights` for lightweight guardrail sliders in Investigator/LIVE.
- Don’t: replace or rename `frontend/static/janusec-platform-complete-LIVE.html`.
- Don’t: default the root to any other template without updating `DEFAULT_FRONTEND`.

## Quick Verification

- LIVE console: `http://localhost:8080/`
- Report: click "Export Investigation Report" or open `/api/v1/report/ingestion?format=html&include_model=true&include_scenarios=true`.
- Metrics: `/static/metrics.html`.
- Integrations: `/static/integrations.html` (configure Slack/Teams/WhatsApp URLs).
- SBOM: `/static/sbom.html` (paste SBOM JSON).
 - Investigator: `/static/multi_log_investigator.html` (submit request, adjust guardrails, send Tier‑2 summary via autogen or Slack fallback).

If you are an AI coding agent, please follow these conventions when modifying the frontend or adding features. This prevents drifting to the wrong UI or regressing the demo experience.

## HopGraph Correlation & Multi-Analyzer Additions

### New Static Page
- Multi-Source Correlator: `frontend/static/csv_multi_analyzer.html` — upload multiple heterogeneous log batches (CSV/JSON/etc.), auto-detect headers, edit field mapping, build a lightweight HopGraph correlation session and view EWMA-smoothed overlap matrix plus explainable factors.

### Session Build Endpoints
- `POST /api/v1/graph/session/build` payload example:
  ```json
  {
    "session_ids": ["batch-abc123","batch-def456"],
    "correlate": true,
    "ewma": true,
    "ewma_alpha": 0.6,
    "mapping": {"user":"user","host":"host","sha256":"file_hash"}
  }
  ```
  Returns a summary including:
  - `correlation` raw overlap counts.
  - `correlation_smoothed` EWMA matrix when `ewma` true.
  - `ewma_alpha` used.
  - `mapping_stats` aggregated canonical field usage.
  - `factors` (high entropy, signature mismatch, large file, NXDOMAIN spike, ASN rarity, batch_missing).
  - `verdict`, `confidence`, `graph_summary`.
- `GET /api/v1/graph/session/{id}` loads from memory or disk (`SESSION_PERSIST_DIR`).

### Persistence & TTL
- Sessions stored as JSON under `SESSION_PERSIST_DIR` (default `data/sessions`). Env vars:
  - `SESSION_PERSIST_DIR` — override directory.
  - `SESSION_TTL_SECONDS` — expire stale session files.
  - `SESSION_CLEAN_INTERVAL_SECONDS` — enable periodic cleanup loop (0 disables).
- EWMA history stored in `EWMA_HISTORY_PATH` (default `data/sessions/ewma_history.json`). Legacy value-only entries are auto-migrated to `(value, timestamp)`.
- `EWMA_HISTORY_TTL_SECONDS` governs pruning in cleanup loop.

### Alpha Validation
- `ewma_alpha` must be in `[0.0, 1.0]`; else 400 `invalid_alpha`.

### Mapping Editor
- Frontend auto-detects CSV headers and suggests canonical fields: `ip`, `ip_dst`, `user`, `host`, `process`, `file_hash`, `domain`, `other`.
- Mapping object forwarded with session build; backend aggregates simple `mapping_stats` for transparency.

### Explainable Factors Tagging
- ASN rarity factors include tags: `CVSS:AV:N`, `KEV:CANDIDATE` (demo tags).
- NXDOMAIN spike factor: `nxdomain_rate_high` when rate >= threshold (`ZEEK_NXDOMAIN_RATE_THRESHOLD` or runtime default 0.35).

### Test Helpers
- Set `TEST_HELPERS_ENABLED=1` for CI routes and deterministic test-mode behaviors (e.g. drain endpoints, faster runtime clearing).

### Cleanup Loop
- When `SESSION_CLEAN_INTERVAL_SECONDS` > 0 a background task prunes expired sessions and EWMA entries.

### Future Extensions (Guidance for Agents)
- Incorporate mapping semantics into factor scoring (e.g., weighting user/process joins).
- Enrich ASN rarity with external reputation feeds; refine KEV tagging.
- Add incident auto-generation from high-confidence multi-stage factors.

### Adaptive EWMA Alpha (New)
- Enable adaptive smoothing by setting `ADAPTIVE_EWMA=1` (or `true/yes`).
- When enabled and the client omits `ewma_alpha` from the build payload, the server derives an alpha from overlap volatility (variance/mean of non-zero pairwise counts).
- Higher volatility lowers alpha (more smoothing); lower volatility keeps alpha higher for reactivity.
- Tunable env vars:
  - `ADAPTIVE_EWMA_BASE_ALPHA` (default `0.6`)
  - `ADAPTIVE_EWMA_MIN_ALPHA` (default `0.3`)
  - `ADAPTIVE_EWMA_MAX_ALPHA` (default `0.85`)
  - `ADAPTIVE_EWMA_VOL_SCALE` (default `0.4`)
- Explicit `ewma_alpha` in payload always takes precedence.

### Domain Diversity Weighting (New)
- Composite path scoring adds `domain_diversity` (distinct prefixes: identity, endpoint, network, data, email, cloud, remote, api/app) normalized against a target of 6.
- Activate influence by setting `SCORING_DIVERSITY_WEIGHT` (e.g. `0.07`).
- Or override multiple weights via `SCORING_WEIGHTS_JSON` (e.g. `{"path":0.25,"diversity":0.07}`).
- Default diversity weight is `0.0` (no impact until configured).

### Mapping Semantics Weighting (New)
- Scoring now includes `mapping_semantics` capturing richness of canonical field coverage in a path.
- High-value fields: `user`, `host`, `process`, `file_hash`, `domain`.
- Bonus tiers: +0.07 when ≥3 high-value present; +0.15 when ≥4 present (normalized).
- Minor incremental bonus for supporting fields: `ip`, `ip_dst`, `role`, `cloud_resource`, `db`, `secret` (+0.02 each capped within normalization).
- Configure influence via `SCORING_MAPPING_WEIGHT` or include `mapping` in `SCORING_WEIGHTS_JSON`.
- Default `mapping` weight is `0.0` until explicitly set.

## Multi-Domain Health & Scoring Admin

- The CSV multi-analyzer plus LIVE console right rail both render the "Multi-Domain Health" banner from the `dependency_status` block returned by `/api/v1/graph/session/build`. Keep `_check_dependency_status` (`src/api/graph_sessions.py`) reporting HopGraph/Redis availability, `last_ok_ts`, `health_last_ok_ts`, and TTL countdown fields so UI banners can show “last success X ago” instead of generic failures.
- Health probes: wire `HOPGRAPH_HEALTH_ENDPOINT` / `REDIS_HEALTH_ENDPOINT` (and any future dependency) so the backend can include HTTP status + latency in `dependency_status`. When adding new backends also update the CSV banner copy to highlight their last-success timestamp.
- Scoring overrides: use the shared helper in `src/core/configuration/scoring_weights.py` and prefer `SCORING_WEIGHTS_JSON` (e.g. `{"mapping":0.45,"diversity":0.07}`) over bespoke env parsing. These weights are surfaced in `summary.scoring_config` so the CSV analyzer panel + LIVE console "Scoring Config" cards stay aligned.
- Admin endpoints to mention when extending UI flows:
  - `/api/v1/admin/scoring/get|update|versions|diff|rollback` (FastAPI router in `src/api/admin_scoring.py`) manages the persisted scoring weight record.
  - `/api/v1/admin/scoring/weights` remains for lightweight overrides used by the LIVE console sliders.
  - `/api/v1/admin/autogen/status|update|trigger` controls the Factor Synthesis auto-incident helpers; `/api/v1/admin/autogen/toggle` is the legacy switch the LIVE console still hits.
- `/api/v1/correlation/multi-domain/config` (POST) and `/api/v1/correlation/multi-domain/config` (GET) power the LIVE console TTL + cleanup controls. When adding new governance toggles, document them here and surface them through that API instead of bespoke env vars so operators can tune from the UI.
- The GET payload now returns `dependency_status` plus a `dependency_config` object (session TTL, cleanup intervals, `DEPENDENCY_HEALTH_CACHE_TTL`, HopGraph/Redis health endpoints, EWMA history TTL). The LIVE console renders these fields inside the Multi-Domain Health panel (`multiDomainConfigMeta` + `multiDomainDependencyMeta`), so keep those keys stable and extend the payload instead of inventing new ad-hoc banners.
- `_check_dependency_status` includes `queued_factor_batches`, `replay_history`, and `last_replay_ts`. The CSV analyzer + LIVE Tier cards read those fields to display “queued batches” and “recovered factors” messaging; whenever you add new degraded-mode states, wire them through the same structure so the banners stay in sync.
- Document any new dependency banner wiring, TTL/cleanup admin knobs, or scoring endpoints here so future agents don't drift from the canonical panel/endpoint mapping.
- `/api/v1/decisions/recent` now includes `hopgraph_context`, `recommendation_catalog`, `recommendation_actions`, `ttl_seconds`, `expires_at`, and `dependency_status`. Always attach additional correlation metadata through the `_merge_decision_meta` helper in `src/api/server.py` so LIVE/SBOM/CSV surfaces render the same context.

## Factor Telemetry & Recommendation Tracking

- `src/api/admin_factor_quality.py` exposes `/api/v1/admin/factors/telemetry`, `/context`, and `/observations`. The LIVE console (metrics.js) auto-polls the telemetry endpoint for the Multi-Domain Health panel and Factor Telemetry cards, so always return `window_precision`, `context_multipliers`, and `factor_rankings` in the payload. If you extend factor-quality metrics, add them there.
- Factor calibration: use `/api/v1/admin/factors/calibration` (GET) to inspect the active JSON config and `/api/v1/admin/factors/calibration/reload` (POST `{path?: "/path/to/cal.json"}` or `{config:{...}}`) to apply new priors without redeploying. The config supports `{ "context_multipliers": {...}, "observations": {"factor": {"tp": N, "fp": M}} }` and feeds both the telemetry snapshot and FactorSynthesisEngine priors. The LIVE console exposes these controls under “Factor Calibration” (right rail) for test-mode overrides.
- `_check_dependency_status` must populate `seconds_since_ok` / `seconds_since_health_ok` so CSV banners and tier summaries can mention "HopGraph healthy 2m ago". When queues drain, `_replay_degraded_factors` records a replay audit; keep that history small and include it in graph-session summaries so UI banners can mention recovered batches.
- Recommendation catalog actions now persist via the incident aggregator. Use `POST /api/v1/incidents/{id}/recommendations/act` (JSON `{action_id,status,actor}`) to mark catalog rows as completed/pending. The LIVE console + SBOM pages both read `recommendation_actions` on incidents/insights to display status chips-preserve that shape (`{id,domain,action,priority,status,updated_ts}`) when adding new catalog sources.
- The CSV analyzer + deep-dive panels fetch `/api/v1/admin/factors/telemetry` on demand to render Tier 1/Tier 2 FP-history drawers. If you change the telemetry schema, update `frontend/static/js/csv_analyzer.js` and `frontend/static/csv_deep_analysis.html` helpers so analysts can still inspect decay settings and factor priors without leaving the UI.

## Optional Crypto Verification Dependencies

- **DKIM verification:** The project can perform cryptographic DKIM checks when `dkimpy` is installed in the runtime environment. Agents and operators should install `dkimpy` (for example, `pip install dkimpy>=0.9.0`) and restart the server to enable `verify_dkim()` paths that require raw RFC822 message bytes. See `docs/enable_dkim.md` for details on payload fields and example usage.

