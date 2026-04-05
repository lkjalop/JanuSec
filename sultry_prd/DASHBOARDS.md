# Sultry Dashboards — Design & Implementation Guide

This document outlines recommended dashboards, metrics, and UI patterns for the Sultry project. It is intentionally implementation-agnostic and draws frontend inspiration from Datadog, CrowdStrike, Splunk, T-Pot / Cowrie and HoneyDB.

Goals
- Provide high-signal SOC views for triage and hunting.
- Support developer-facing supply-chain views for SBOM/vuln triage.
- Offer operational health metrics for the pipeline (ingest rates, backlog, EWMA drift).
- Keep artifacts repository-friendly (docs + sample JSON exporters can be added later).

Metric Naming Conventions
- Use clear, Prometheus-style names for metrics that are produced by the pipeline.
- Example prefixes: `sultry_`, `sultry_events_`, `sultry_incidents_`, `sultry_honeypot_`, `sultry_sbom_`.
- Example metric naming suggestions:
  - `sultry_events_total{domain, factor}` — counter of matched factor events.
  - `sultry_events_by_source_total{source}` — per-source ingestion counter.
  - `sultry_incident_score_max{incident_id}` — gauge of highest per-incident score.
  - `sultry_incident_confidence{incident_id}` — gauge 0..1 confidence for incidents.
  - `sultry_honeypot_hits_total{host, factor}` — honeypot-specific hits counter.
  - `sultry_correlation_sessions_active` — gauge of active correlation sessions.
  - `sultry_ewma_intensity` — EWMA-smoothed correlation intensity (0..1).
  - `sultry_ingest_backlog_seconds` — backlog duration for ingest queue.
  - `sultry_processing_latency_seconds` — histogram for processing time by stage.

Dashboard Roles & Pages
- Overview (SOC)
  - Purpose: give SOC analysts a quick sense of overall threat activity and top incidents.
  - Panels:
    - Incidents by domain (bar chart)
    - Top factor & top paths (table)
    - EWMA intensity timeline (line)
    - Top entities (users/hosts/IPs) with factor counts
    - Recent high-confidence incidents (list)

- Investigator / Timeline View
  - Purpose: examine a single incident or entity timeline with event annotations.
  - Panels:
    - Timeline with annotated factor events (hoverable, links to raw event)
    - Event detail pane (raw + normalized + enrichment metadata)
    - Related sessions / correlated path graph (small network graph)

- Hunt / Analytics
  - Purpose: enable searching large event sets by factor, time-window, or entity.
  - Panels:
    - Factor frequency heatmap by domain/time
    - Filtered event table with deep links to investigation
    - Pivot panels (show top ASNs, TLDs, processes for filtered set)

- Supply-Chain / SBOM
  - Purpose: show SBOM ingestion, vuln counts, flagged artifacts.
  - Panels:
    - Components by severity
    - New/changed vulnerable components timeline
    - Map of dependencies (small force graph)

- Operational / Metrics
  - Purpose: monitor pipeline health and performance.
  - Panels:
    - Ingest rate by source
    - Processing latency per stage (normalizer/enricher/scorer/correlator)
    - Queue/backlog gauges
    - Service uptime & error rates

Panel Examples & Queries (Prometheus-style)
- EWMA intensity (1m avg):
  - `avg_over_time(sultry_ewma_intensity[1m])`
- Top factors in last hour (counter increase):
  - `topk(10, increase(sultry_events_total[1h]))`
- Ingest lag (seconds):
  - `max(sultry_ingest_backlog_seconds)`
- Active sessions:
  - `sultry_correlation_sessions_active`

Alerting Suggestions
- High-confidence incident: `sultry_incident_confidence > 0.85` for sustained 5m -> trigger paging rule.
- EWMA surge: `sultry_ewma_intensity > 0.7` (5m) -> create SOC incident candidate.
- Pipeline backlog: `sultry_ingest_backlog_seconds > 600` -> alert ops.

Frontend Inspiration & UX Patterns
- Datadog / Splunk: central overview with quick filters, large time-series panels, customizable dashboards.
- CrowdStrike: entity-first views (host/user) with right-hand action panel for responses.
- T-Pot / Cowrie / HoneyDB: honeypot dashboards emphasize attacker behavior timelines, sample payloads, and geolocation.

Suggested UI Layout (left-nav, center timeline, right actions)
- Left: navigation (Overview, Investigate, Hunt, SBOM, Integrations)
- Center: main content and time-range controls
- Right: active item details, quick-actions (create incident, export report, send to SIEM)

Export / Integrations
- Provide export options: HTML report, JSON, webhook to SIEM, Slack/Teams notifications.
- Prometheus metrics should be exported at `/metrics` (Prometheus exposition format) and follow naming conventions above.
- Grafana dashboards can be kept in `sultry_prd/dashboards/grafana/` as importable JSON.

Implementation Notes
- Keep `DASHBOARDS.md` as the single source of design for now. If you later want runnable artifacts I will scaffold example Grafana JSON and a static HTML demo under `sultry_prd/dashboards/`.
- Avoid modifying the LIVE console (`frontend/static/janusec-platform-complete-LIVE.html`). If adding a small demo, create a separate static page under `frontend/static/` and wire a left-sidebar link only if approved.

Next steps (optional):
- I can scaffold sample Grafana dashboard JSON and a Prometheus metrics example under `sultry_prd/dashboards/`.
- I can add a JSON schema and generator to map `full/factors_catalog_full.json` -> sample metric names and Grafana panels automatically.

---
Design author: Sultry PRD automation
Date: 2025-11-13
