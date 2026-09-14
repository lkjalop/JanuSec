**Janusec Platform Architecture & 21-Step Pipeline**

Purpose
- Provide a concise architecture overview, ASCII architecture diagram, detailed description of the 21-step pipeline used by the `Deep Analyze` flow, HopGraph attack reconstruction summary, manual log analysis guidance, and LLM tiering + persona report generation.

High-level Architecture (ASCII)

```
                           +---------------------+
                           |   Ingest Layer      |  <-- CSV / Excel / JSON uploads, Live Console
                           |  (Upload API)       |
                           +---------+-----------+
                                     |
                     +---------------v---------------+
                     |  Preprocessing / Tabular SRV  |  (tabular sessions, headers, store bytes)
                     +---------------+---------------+
                                     |
                     +---------------v---------------+
                     |  Deep Analyze Pipeline        |  (21 stages, triage, LLM stages)
                     |  (run_deep_analyze_pipeline)  |
           +---------+---------------+---------------+---------+
           |                         |                         |
  +--------v--------+       +--------v--------+       +--------v--------+
  | Correlation /    |       | Enrichment /    |       | LLM / Explain   |
  | HopGraph Builder |       | Reputation / ASN|       | (Tier1 / Tier2)  |
  +--------+--------+       +--------+--------+       +--------+--------+
           |                         |                         |
           +-----------------+-------+-------------------------+
                             | Persist / Reports / UI       |
                             | (data/assessments, sessions) |
                             +------------------------------+

```

Components
- Ingest Layer: `POST /api/v1/csv/upload` — converts Excel -> CSV, parses JSON, creates tabular sessions with headers.
- Tabular Session Store: lightweight in-memory registry `TABULAR_SESSIONS` plus persisted CSV bytes for pagination/UI.
- Deep Analyze Pipeline: `run_deep_analyze_pipeline` executes 21 steps (enumerated below) and persists an `assessment` JSON under `data/assessments/<org>/<date>/assessment-<id>.json`.
- Backfill Orchestrator: `csv_deep_analyze_auto_backfill` schedules `_run_backfill` tasks; uses `BACKFILL_JOBS` persisted under `data/sessions/backfill_jobs`.
- HopGraph Correlator: `POST /api/v1/graph/session/build` builds lightweight graphs from multiple sessions; returns correlation matrices and explainable factors.
- LLM Tiering: Tier1 lightweight summarization; Tier2 deep LLM summarizer via `src.analysis.auto_llm` producing persona-based reports and playbooks.

21-Step Pipeline (short descriptions)
1. ingest_logs: Accept raw rows and annotate ingest metadata.
2. parse_events: Parse and normalize fields (timestamps, IPs, file paths).
3. normalize_fields: Map column names to canonical fields (file_path, sha256, process_name).
4. enrich_ip_whois: ASN and geo-location enrichment for IPs.
5. enrich_asn: ASN rarity scoring and tagging.
6. enrich_reputation: Reputation lookups (file hash, domain intelligence).
7. cluster_sessions: Aggregate closely related rows into sessions by actor/host.
8. identify_hosts: Host resolution and canonicalization.
9. identify_users: Map user identifiers and normalize role/context.
10. process_binaries: File analysis heuristics and static attributes extraction.
11. extract_indicators: Derive IOCs (hashes, domains, IPs, URLs).
12. correlate_indicators: Link indicators across rows and external feeds.
13. score_paths: Compute path-scoring (DREAD-like) and triage_score.
14. build_hop_graph: Add row entities to hop graph for correlation across sessions.
15. entropy_analysis: Compute distinctness/uniqueness features impacting rarity scores.
16. temporal_correlation: Time-based clustering and EWMA computations for rate anomalies.
17. anomaly_detection: Flag outliers via heuristics and ML models (if present).
18. generate_findings: Produce row-level findings including `factors` and `recommendations`.
19. prioritize_f: Rank results and set `risk_label` and `risk_level`.
20. llm_inference: (optional) Tier1 LLM summaries (fast, templated) for UI rows.
21. persist_and_notify: Persist assessment JSON, emit events for UI, backfill, and reports.

HopGraph Attack Reconstruction (brief)
- Goal: identify overlapping entities (file hash, host, user, domain) across multiple batches to reconstruct multi-stage attacks.
- Method:
  - Canonicalize fields to nodes (host:user, file:sha256, domain, ip).
  - Build edges using observed co-occurrence in rows and sessions.
  - Weight edges by frequency and rarity; smooth via EWMA for noisy signals.
  - Extract high-weight paths and annotate with factors (NXDOMAIN spike, ASN rarity, KEV tags).

Manual Log Analysis Guidance
- Start with the HopGraph: find high-overlap clusters between endpoint and network sessions.
- Use the CSV Analyzer `inspect` to profile columns and map canonical fields.
- Prioritize rows with high `triage_score` and those with rare ASN/file hashes.
- Drill down: view the `row.raw` to inspect original columns and verify remapping.

LLM Tiering, Persona Reports, and Playbooks
- Tier1: small, fast templated summaries inserted into the UI for quick review. Outputs include one-line verdict, top factors, recommended immediate action.
- Tier2: deep LLM summarizer called via `csv/tier2_investigate` or `LLMAssessmentClient` which builds context and returns a persona-based narrative report (investigator, SOC manager, CISO) and suggested playbook steps.
- Persona Reports: a persona maps the audience and format of the report (e.g., `investigator` -> technical steps and artifacts; `exec` -> impact summary and suggested SLAs).

User Flow Example
1. Upload CSV via UI or API.
2. System creates `assessment` and returns `assessment_id`.
3. User opens CSV Analyzer; UI shows rows with Tier1 summaries and triage score.
4. Optionally: click `Start Backfill` to run adaptive backfill; progress shows via `/auto_backfill/{id}/status`.
5. Click row -> request `Tier2` investigate; LLM returns persona-based report and suggested playbook.
6. Export investigation report or send to SIEM via integrations.

Operational Notes
- Persisted paths: `data/assessments/...` and `data/sessions/backfill_jobs`.
- Config via env vars: `BACKFILL_*`, `SESSION_PERSIST_DIR`, `TEST_HELPERS_ENABLED`.
- For debugging mapping issues, inspect `BACKFILL_JOBS[*]['debug']` and assessment `rows` structure (list-of-lists vs dicts).

Next steps / Improvements
- Move remapping heuristics into a shared utility and ensure ingestion emits canonical dict rows.
- Add confidence-normalization rules upstream during ingestion.
- Add more robust rate-limiting and concurrency controls for backfill workers in production.

References
- Live console: `frontend/static/janusec-platform-complete-LIVE.html` (UI anchors)
- Backfill and remapper: `src/api/csv_endpoints.py`
- Pipeline: `src/api/deep_analyze_endpoints.py`
