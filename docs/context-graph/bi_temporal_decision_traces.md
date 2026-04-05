# Bi-Temporal Decision Traces for Janusec Context Graph

This document proposes a comprehensive approach to integrating bi-temporal decision traces into Janusec’s context graph architecture to improve explainability, auditability, multi-source correlation, missing logs detection, tiered LLM summaries, and cyber risk quantification.

## Why Bi-Temporal Decision Traces

Bi-temporal modeling tracks both real-world validity and system transaction timelines for each decision-related artifact. This enables:
- Point-in-time reconstruction: replay any decision “as-of” a historical moment.
- Provenance clarity: what inputs existed, when they were ingested, and which policies/exceptions applied.
- Detection of ingestion gaps: differences between valid time and transaction time reveal missing or delayed logs.
- Reliable explainability: LLM summaries grounded in traceable evidence and policy evaluations rather than free-text.

We adopt a four-timestamp model per trace artifact:
- `t_valid`: when information became true in the real world.
- `t_invalid`: when it ceased being true in the real world.
- `t_created`: when the system recorded/ingested the artifact.
- `t_expired`: when the artifact was superseded or archived by the system.

## Core Trace Schema (Property Graph)

Minimal decision-trace entities and relationships to add alongside existing HopGraph session outputs:

Entities (nodes):
- `Decision`: a discrete correlation or verdict event (session-scoped or incident-scoped).
- `Evidence`: normalized inputs (alerts, logs, file hashes, identities, domains, flows) with source metadata.
- `PolicyEval`: the policies, rules, scores, and exceptions evaluated.
- `Exception`: any overrides or special-case handling invoked.
- `Outcome`: the actionable result (e.g., incident created, recommendation emitted).
- `Precedent`: prior similar decisions linked for precedent-based reasoning.
- `Session`: multi-source correlation session container (already present).
- Domain entities referenced by evidence: `Identity`, `Device`, `Host`, `Process`, `FileHash`, `Domain`, `IP`, `CloudResource`.

Relationships (edges):
- `(:Decision)-[:CONSUMES]->(:Evidence)`
- `(:Decision)-[:EVALUATES]->(:PolicyEval)`
- `(:PolicyEval)-[:INVOKED_EXCEPTION]->(:Exception)`
- `(:Decision)-[:PRODUCES]->(:Outcome)`
- `(:Decision)-[:REFERENCES_PRECEDENT]->(:Precedent)`
- `(:Evidence)-[:OBSERVED_ON]->(:Device|:Host|:Identity|:CloudResource|:IP|:Domain)`
- `(:Session)-[:CONTAINS]->(:Decision|:Evidence|:PolicyEval|:Outcome)`

Properties (on nodes and edges):
- Bi-temporal: `t_valid`, `t_invalid`, `t_created`, `t_expired`.
- Provenance: `source_system`, `connector`, `ingest_pipeline_step`, `confidence`.
- Compliance: `policy_id`, `policy_version`, `scoring_config_version`, `explainable_factors`.
- Identity stitching: `canonical_id`, `aliases`, `stitch_quality`.
- Mapping semantics: `fields_present`, `high_value_fields_count`, `supporting_fields_count`.

## Integration Points in Janusec

Use HopGraph’s session build as the orchestration point and extend the outputs while preserving current UI. Key files and surfaces to integrate:
- Session build and load: [src/api/graph_sessions.py](src/api/graph_sessions.py)
- LIVE console and static pages: [frontend/static/janusec-platform-complete-LIVE.html](frontend/static/janusec-platform-complete-LIVE.html)
- Scoring weights governance: [src/core/configuration/scoring_weights.py](src/core/configuration/scoring_weights.py), [src/api/admin_scoring.py](src/api/admin_scoring.py)
- App routing and serving: [src/api/app.py](src/api/app.py)

Recommended additions:
- Add `decision_trace` block to `/api/v1/graph/session/build` response with above entities/relationships summarized.
- Add `as_of` query support to `/api/v1/graph/session/{id}` for bi-temporal point-in-time reads.
- Persist session and decision-trace JSON under `SESSION_PERSIST_DIR` with existing TTL/cleanup behaviors; include adaptive EWMA history linkage.

## Where to Apply (Pipeline Phases)

Apply decision-trace instrumentation across the pipeline to capture end-to-end context:
- Ingest: record `Evidence` with `t_valid` (from event timestamp) and `t_created` (ingestion time); record `source_system`, `connector`.
- Normalize/Map: attach `fields_present`, mapping semantics, and `stitch_quality` for identity/entity resolution.
- Correlate: construct `Decision` nodes per correlation step; attach `explainable_factors`, EWMA-derived overlaps, and `mapping_stats`.
- Score/Govern: add `PolicyEval` with `policy_id`, `policy_version`, `scoring_config_version`; attach any `Exception` invoked.
- Outcome: create `Outcome` with actions (incident creation, recommendation catalog entries) and TTL; link to `Decision`.
- Precedent/Replay: link to prior similar `Decision` via `REFERENCES_PRECEDENT` for precedent reasoning; support replay under `as_of`.

Hook points in the event pipeline:
- Extend `process_workers` steps to emit trace artifacts during normalize/correlate/score phases.
- Ensure idempotent writes with session-aware keys so reloads don’t duplicate trace nodes.

## How It Helps: Domains & Use Cases

- Endpoint/Host/Process: time-scoped process trees and file hashes linked to decisions; bi-temporal gaps expose delayed EDR telemetry.
- Identity/Email: stitch aliases across `user`, `UPN`, `SID`, `mail`; precedence links show historical exceptions (e.g., service accounts).
- Network/DNS: capture NXDOMAIN spikes with valid vs ingest time deltas; path scoring benefits from domain diversity and EWMA history.
- Cloud/SaaS: represent resource roles and policy contexts; decision traces show which control failed and when.

## Missing Logs Detection

Bi-temporal deltas power robust gap detection:
- Define ingestion latency windows per source; compute `delta = t_created - t_valid`.
- Trigger factors when `delta` exceeds thresholds or when `t_invalid` occurs before `t_created` (late arrival).
- Detect holes by comparing expected volume vs observed volume per window; emit `batch_missing` factors and quantify blind-spot risk.
- Surface gaps in Multi-Domain Health via `dependency_status` with last-success timestamps and queued batches.

## Tiered LLM Summaries (T1 vs T2)

- Tier 1 (Analyst Triage): concise `Decision Trace Explainer` card built from `Decision`, `Evidence`, `PolicyEval`, `Outcome` with bi-temporal context; includes EWMA overlap and mapping semantics coverage.
- Tier 2 (Investigation Deep Dive): GraphRAG-lite summaries that combine global community descriptions (for corpus-wide themes) with local entity neighborhoods; render paths with factors and time constraints.
- Grounding: LLMs retrieve via trace nodes, not raw text, minimizing hallucinations and enabling direct link-back to evidence.

## Multi-Source Correlation & Triage

Decision traces strengthen correlation:
- Identity join quality and mapping semantics weight increase confidence when ≥3–4 high-value fields are present.
- Domain diversity adds breadth to path scoring; EWMA smoothing stabilizes overlap matrices.
- Precedent links accelerate similarity matching across sessions; short pathfinding between entities highlights lateral-movement and blast-radius.

## Cyber Risk Quantification

Decision traces provide calibrated inputs for risk models:
- Event likelihood: derive from historical decision frequencies and detection precision ($p$).
- Impact: map affected asset criticality and blast-radius path scores to dollar impact ($I$).
- Expected loss: $\mathbb{E}[Loss] = \sum_i p_i \cdot I_i$ across decision classes.
- Control effectiveness: measure ingestion lag, mapping coverage, and factor precision to update priors.
- Residual risk: quantify blind-spot exposure from missing logs and weak stitching; visualize per domain.

## API Changes (Minimal)

- `POST /api/v1/graph/session/build`
  - Add optional `as_of` argument; when present, compute overlaps and factors using artifacts valid at `as_of`.
  - Return `decision_trace` with lists of `decisions`, `evidence`, `policy_evals`, `outcomes`, `precedents` (summarized), each with bi-temporal fields.
- `GET /api/v1/graph/session/{id}`
  - Support `as_of` for point-in-time reads.
- Admin and Health
  - Surface `scoring_config_version` and dependency timestamps in summaries for governance and UI banners.

## Storage & Persistence

- Continue persisting sessions under `SESSION_PERSIST_DIR` with TTL governed by `SESSION_TTL_SECONDS` and cleanup loop (`SESSION_CLEAN_INTERVAL_SECONDS`).
- Store EWMA history under `EWMA_HISTORY_PATH`; ensure migration to `(value,timestamp)` shape; prune using `EWMA_HISTORY_TTL_SECONDS`.
- Decision-trace JSON co-located with sessions for demo; add optional graph backend adapter for Neo4j/Neptune when enabled.

## UI Additions (LIVE Console)

- Right rail: add `Decision Trace` panel showing time-scoped evidence and policy evaluations; link to report export.
- As-of control: small datetime picker enabling point-in-time view; persist in query params and headers.
- Health banners: enrich with ingestion lag stats and blind-spot indicators derived from bi-temporal deltas.

## Governance & Compliance

- Audit schema: include timestamps, query classification, traversal paths, nodes accessed, explanation text for EU AI Act high-risk readiness.
- RBAC: restrict property-level access for sensitive attributes in graph backends; ensure audit logging of trace reads.
- Versioning: persist `scoring_config_version` and policy versions; add `/api/v1/admin/scoring/versions|diff|rollback` integration in summaries.

## Metrics & Telemetry

- Precision windows, factor rankings, and context multipliers exposed via [src/api/admin_factor_quality.py](src/api/admin_factor_quality.py) to drive the Multi-Domain Health panel.
- New metrics: ingestion latency distribution per source; mapping coverage; stitch quality; pathfinding latency.

## Risks & Mitigations

- Supernodes and traversal cost: partition via time-sliced proxy nodes; index relationship properties for time-bounded queries.
- Data poisoning: validate connectors, rate-limit traversal depth, sign trace artifacts; add anomaly detection for unusual path patterns.
- Privacy: encrypt sensitive properties, apply differential privacy for analytics, and disable schema introspection in production.

## Implementation Plan

### 0–2 Weeks (Quick Wins)
- Add `decision_trace` summaries to session build/load responses with four-timestamp fields.
- Implement `as_of` parameter and basic point-in-time filtering.
- Extend identity stitching (`canonical_id`, `aliases`, `stitch_quality`) and mapping semantics in session outputs.

### 3–6 Weeks
- Introduce `GraphStore` interface with in-memory and optional Neo4j adapter; write decisions/evidence/policy evals as nodes/edges.
- Add pathfinding for blast-radius and lateral movement; render small paths in LIVE console.
- Wire new metrics into Multi-Domain Health and factor telemetry endpoints.

### 7–12 Weeks
- Expand policy graph and exceptions; integrate versioned scoring governance in trace summaries.
- Add Tier 1/2 LLM summary generation grounded on trace nodes; include export in report endpoints.
- Harden with RBAC, audit logs for trace queries, and traversal rate limits.

## Acceptance Criteria

- `as_of` reads return deterministic trace snapshots that match historical decisions.
- LIVE console renders Decision Trace panel and shows ingestion lag indicators.
- Multi-source correlation confidence increases where mapping semantics and identity stitching are rich (≥3–4 high-value fields).
- Risk quantification outputs (expected loss bands, residual blind-spot indicators) can be derived from trace data and surfaced in summaries without manual curation.

---

By integrating bi-temporal decision traces, Janusec advances toward context-graph-native operations: explainable, auditable, multi-domain correlation with practical pathways to cyber risk quantification and governance readiness—all while preserving your lightweight, demo-friendly LIVE console and existing APIs.