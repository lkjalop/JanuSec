# Connector Integration, HopGraph Reconstruction, and LLM T1/T2 Enrichment – Implementation Plan

This document consolidates connector API/webhook integration guidance, maps data into the existing 21+ stage pipeline, integrates HopGraph attack reconstruction, and outlines frontend UI/UX upgrades to improve Tier‑1 (T1) and Tier‑2 (T2) LLM summaries. It draws on and extends the guidance from:
- [HOPGRAPH_MULTI_DOMAIN_ATTACK_RECONSTRUCTION.md](HOPGRAPH_MULTI_DOMAIN_ATTACK_RECONSTRUCTION.md)
- [connector_coverage_strategic_improvement.md](connector_coverage_strategic_improvement.md)

## Objectives
- Ingest logs and livestreamed events via connector APIs/Webhooks for listed tools (Zeek/Suricata/Wazuh, EDR/XDR, Cloud posture/security tools, Identity providers, App/API gateways).
- Normalize into canonical fields and flow through the 21+ stage pipeline.
- Build HopGraph sessions and persist snapshots; enable correlation, EWMA smoothing, and explainable factor tagging.
- Improve the LIVE console and CSV analyzers with inline actions and summaries.
- Enrich LLM T1 quick summaries and T2 deeper investigations with HopGraph, mapping semantics, domain diversity, and adaptive EWMA context.

---

## Ingestion: Connector APIs and Webhooks

**Approach:** Use existing routers to accept JSON webhook payloads and batch uploads, adding targeted adapters when necessary. Ensure `x-api-key` and optional tenant scoping.

- **Webhooks:** [src/api/app.py](src/api/app.py) includes middleware `WebhookGuardMiddleware` and mounts integrations endpoints (POST `/api/v1/webhooks/*`).
- **Unified Ingest:** Routers for Zeek/Suricata/Wazuh and others (e.g., `unified_ingest_router`) are mounted in [src/api/app.py](src/api/app.py#L1132-L1205).
- **CSV/Static Uploads:** Batch uploads via `POST /api/v1/upload/files` and CSV endpoints are included in [src/api/app.py](src/api/app.py#L1205-L1250).

**New/Extended Adapters (examples):**
- CrowdStrike/Falcon, SentinelOne, Defender for Endpoint, Wazuh, Suricata: standardize observables (`user`, `host`, `process`, `file_hash`, `ip`, `domain`).
- Cloud (AWS Config/Security Hub, Azure Defender/Policy, GCP SCC, OCI Cloud Guard): leverage scheduled JSON adapters wired in [src/api/app.py](src/api/app.py#L758-L942) to post data into `/api/v1/stream/ingest` or specific routers.

**Actions:**
- Confirm each connector maps to canonical fields; add lightweight mapping tables per source.
- For webhooks, document expected HMAC/shared secret when applicable and configure `WebhookGuardMiddleware`.

---

## Pipeline Mapping (21+ Stages)

Incoming events are processed through normalization, enrichment, scoring, correlation, and incidenting. Key existing stages are wired via routers in [src/api/app.py](src/api/app.py#L1132-L1398) and supporting modules.

- **Normalization:** Map source-specific payloads to canonical fields.
- **Enrichment:** IP/ASN, KEV CVEs, reputation feeds.
- **Scoring:** DREAD scorer, mapping semantics weighting, domain diversity weighting.
- **Correlation:** Co-occurrence, temporal pivots, HopGraph path linking.
- **Streaming/SSE:** `/api/v1/decisions/recent`, live dashboard endpoints.
- **Incidenting:** Incident aggregator snapshots; optional auto-incident generator.

Additions referenced in AGENTS.md:
- Adaptive EWMA alpha (volatility-derived when `ADAPTIVE_EWMA=1`).
- Domain diversity weighting via `SCORING_DIVERSITY_WEIGHT`.
- Mapping semantics weighting via `SCORING_MAPPING_WEIGHT`.

---

## HopGraph Integration and Persistence

- **Session Build:** `POST /api/v1/graph/session/build` and `GET /api/v1/graph/session/{id}` are mounted via `graph_session_router`. Confirm mount in [src/api/app.py](src/api/app.py#L1327-L1398).
- **Persistence/TTL:** Sessions stored under `SESSION_PERSIST_DIR` or SQLite when `SESSION_PERSIST_SQLITE_PATH` is set. Cleanup loop mounted in [src/api/app.py](src/api/app.py#L585-L742).
- **EWMA History:** `EWMA_HISTORY_PATH` with TTL; cleanup loop prunes entries.
- **Explainable Factors:** Include `factors` like ASN rarity (tags: `CVSS:AV:N`, `KEV:CANDIDATE`), NXDOMAIN spike (`nxdomain_rate_high`), `batch_missing`, etc.

**Operational Hooks:** Background snapshot/prune and domain pivot sequence detection in [src/api/app.py](src/api/app.py#L420-L507).

---

## Frontend UI/UX Upgrades

Primary console is the LIVE page: [frontend/static/janusec-platform-complete-LIVE.html](frontend/static/janusec-platform-complete-LIVE.html). Add sidebar entries to new static pages and inline actions on analyzers.

- CSV Multi-Analyzer page: [frontend/static/csv_multi_analyzer.html](frontend/static/csv_multi_analyzer.html) – supports multi-source uploads, header auto-detect, mapping editor, EWMA-smoothed overlap matrix.
- CSV Analyzer inline details and action buttons: ensure `tr.csv-inline-details` insertion and row-click toggling in [frontend/static/js/csv_analyzer.js](frontend/static/js/csv_analyzer.js).
- LIVE console actions are bound to `createIncidentFromRecent()`, `exportInvestigationReport()`, `sendToSiem()`.

**Planned UI Edits:**
- Add hopgraph session viewing and factor chips to the LIVE console’s right panel.
- Inline “LLM T1” and “Deep Explain (T2)” buttons appear under expanded rows in CSV analyzers.

---

## LLM T1/T2 Summary Enrichment

- **T1 (Quick):** Summarize most recent decision factors, top overlaps, and immediate risk signals; include compact HopGraph path snippet and domain diversity score.
- **T2 (Deep):** Add adaptive EWMA context, mapping semantics richness, pivot sequences, and incident linkage. Provide suggested actions and affected assets.

Leverage routers:
- `tier2_router` and `llm_endpoints_router` in [src/api/app.py](src/api/app.py#L214-L268, src/api/app.py#L290-L305) for server-side generation endpoints.

---

## Concrete Changes (Files and Lines)

Below are targeted, minimal edits to wire the features. Line references are approximate and intended for navigation.

- Mount static pages (if needed) and ensure console routing:
  - Confirm serving of LIVE console in [src/api/app.py](src/api/app.py) and add a link in [frontend/static/janusec-platform-complete-LIVE.html](frontend/static/janusec-platform-complete-LIVE.html) left sidebar to `csv_multi_analyzer.html`.

- CSV Analyzer inline details toggle and buttons:
  - Ensure `tr.csv-inline-details` insertion and row-click handler in [frontend/static/js/csv_analyzer.js](frontend/static/js/csv_analyzer.js). If missing or incomplete, add a document click handler that calls `openCsvRowDetails(idx)` when clicking non-interactive portions of `tr[data-row]`.

- HopGraph factor and alpha display in UI:
  - Add a small factor chips section in LIVE console right panel: [frontend/static/janusec-platform-complete-LIVE.html](frontend/static/janusec-platform-complete-LIVE.html) – bind to `/api/v1/graph/session/{id}` and include `ewma_alpha`.

- LLM endpoints usage in UI:
  - T1/T2 buttons in CSV analyzers should call server routes exposed via `llm_endpoints_router` and `tier2_router`. Wire fetch calls with `{'x-api-key': localStorage.apiKey || 'devkey123'}`.

- Backend cleanup and persistence:
  - Confirm `SESSION_CLEAN_INTERVAL_SECONDS` > 0 enables cleanup loop in [src/api/app.py](src/api/app.py#L585-L742). For SQLite persistence, ensure `SESSION_PERSIST_SQLITE_PATH` is set; schema initialization occurs in [src/api/app.py](src/api/app.py#L306-L335).

---

## API Contracts and Headers

- Always send `x-api-key` (default dev key `devkey123` in static pages). Tenants can scope via `x-tenant-id`.
- For vendor webhooks, configure HMAC/shared secret in `WebhookGuardMiddleware` and any per-integration config endpoints.

---

## Configuration Flags

- `DEFAULT_FRONTEND=console` ensures LIVE console is served at `/`.
- HopGraph:
  - `SESSION_PERSIST_DIR`, `SESSION_TTL_SECONDS`, `SESSION_CLEAN_INTERVAL_SECONDS`
  - `EWMA_HISTORY_PATH`, `EWMA_HISTORY_TTL_SECONDS`
  - `ADAPTIVE_EWMA=1` with base/min/max/vol scale env vars.
- Scoring weights:
  - `SCORING_DIVERSITY_WEIGHT` or `SCORING_WEIGHTS_JSON` with `{"path":..., "diversity":...}`
  - `SCORING_MAPPING_WEIGHT` or `SCORING_WEIGHTS_JSON` including `"mapping"`

---

## Validation Steps

- Upload multi-source logs on Multi-Analyzer; verify mapping editor and EWMA matrix render.
- Build HopGraph session via API; confirm factors and verdict in response and UI.
- Click a CSV row; `tr.csv-inline-details` should expand with buttons. Trigger T1/T2 and confirm summaries.
- Check `/metrics` for scrape; run SSE decisions stream; confirm incident snapshot persistence and cleanup.

---

## Future Improvements

- Integrate external reputation feeds into ASN rarity; refine KEV tagging heuristic.
- Incorporate mapping semantics into factor scoring more deeply (e.g., weighting user/process joins).
- Add auto-incident generation from multi-stage high-confidence factors and expose quick actions in UI.

---

## References to Improve

- Extend [HOPGRAPH_MULTI_DOMAIN_ATTACK_RECONSTRUCTION.md](HOPGRAPH_MULTI_DOMAIN_ATTACK_RECONSTRUCTION.md) with:
  - Explicit JSON examples for session build requests and responses.
  - Visualization guidelines for factor chips and path snippets in UI.
  - Notes on adaptive EWMA and volatility-derived alpha.

- Extend [connector_coverage_strategic_improvement.md](connector_coverage_strategic_improvement.md) with:
  - Batches of connectors prioritized by signal coverage and ease of mapping.
  - Security/business/market impact framing per batch.
  - Specific mapping tables to canonical fields and expected webhook formats.

---

## Quick Runbook

1. Set env:
   - `DEFAULT_FRONTEND=console`, `SESSION_CLEAN_INTERVAL_SECONDS=300`, `ADAPTIVE_EWMA=1`, `SCORING_DIVERSITY_WEIGHT=0.07`, `SCORING_MAPPING_WEIGHT=0.07`.
2. Start API and serve static console.
3. Upload logs via Multi-Analyzer; verify mappings.
4. Build HopGraph session; check factors and EWMA.
5. Use T1/T2 actions on expanded rows; confirm enriched summaries.
