# Sultry AI — Product Requirements & LLM Analysis Prompt

Document purpose: single-source Product Requirements Document (PRD) + analysis prompt for automated LLM review and downstream engineers. This file is intended to be unpacked into a new repository/folder and analyzed by LLMs to produce design proposals, tests, and implementation plans.

Date: 2025-11-13

---

**How to use this file (LLM-first workflow)**
- **Primary task for LLMs:** Read this PRD, identify missing assumptions, produce a prioritized implementation plan (epics + milestones), list measurable acceptance criteria, and output a JSON artifact describing architecture, data schema, retention, tests, and risk map.
- **Output format requested from LLM:** JSON with these top-level keys: `summary`, `assumptions`, `architecture`, `mvp`, `data_schema`, `apis`, `plugin_model`, `security`, `storage_retention`, `mlops_plan`, `tests`, `risk_and_mitigation`, `migration_from_janusec`, `next_steps`.
- **Follow-up:** Human engineers review LLM output and provide further feedback. Iterate until plan is stable.

---

**Executive summary / Vision**
- **Goal:** Build a modular deception correlation engine and honeypot orchestration platform that is: lightweight enough to run on edge devices (Raspberry Pi) for data collection, and scalable to enterprise clusters with GPU-backed LLM/RAG for deep analysis.
- **Primary value:** Collect high-signal attacker telemetry using deceptive assets, correlate across temporal and graph contexts, produce explainable decisions and evidence for threat intel and SOC workflows.

---

**MVP scope**
- **Domains:** Network, Endpoint, Identity (broad and extensible).
- **Sensors (MVP):** HTTP(S) honeypot, SSH honeypot, Canary file on endpoint, LDAP/AD honey endpoint, basic SMB/RDP stub (optional). Minimal telemetry: connection attempts, auth attempts, file access, form submissions.
- **Processing stack (MVP):** Edge agents → secure ingest (NATS/Kafka optional) → Sultry Core (Tier0 L1 cache + Tier1 fast detectors + simple rule engine). Tier2 RAG/LLM optional and disabled by default on edge.
- **Deliverables:** Ingest API, normalized event schema, basic HopGraph-like micrograph, factor engine, UI with event timeline and chain graph, plugin SDK for factor plugins.

---

**High-level architecture (short)**
- Edge sensors: lightweight agent (Python/Go), local durable queue, TLS + mTLS support, local config for redaction.
- Messaging: NATS or Kafka (bridgeable). For Pi-only deployments, use MQTT/NATS with file-backed buffer.
- Ingest & API: FastAPI service with auth, rate limits, and signature verification.
- Processing pipeline: Tier0 cache (Redis or in-process), Tier1 detectors (IsolationForest, EWMA), HopGraph micrograph, rule/factor engine, Tier2 RAG/LLM (optional).
- Storage: Postgres + Timescale + pgvector for enterprise; SQLite+sqlite-vss for minimal runs.

---

**Minimal normalized event schema (MVP)**
Use a JSON schema, versioned. Minimal required fields:
- `event_id` (UUID)
- `timestamp` (ISO8601 UTC)
- `sensor_id` (string)
- `sensor_type` (enum: `web`, `ssh`, `smb`, `rdp`, `canary_file`, `ldap`, `other`)
- `event_type` (enum: `conn_attempt`, `auth_attempt`, `file_access`, `form_submit`, `cmd_exec`, `payload_download`)
- `src_ip`, `src_port`, `dst_ip`, `dst_port`
- `dst_service` (string)
- `user` (string|null) — redacted by default
- `artifact` (filename, url path, or resource id)
- `raw_hash` (sha256 of raw payload)
- `payload_ref` (object storage pointer or local buffer pointer)
- `schema_version` (string)
- `meta` (JSON object for plugin/extension use)

Add example JSON in a `examples/` folder when unpacked.

---

**Plugin model & packaging (summary)**
- Types: `ingest_adapter`, `factor`, `correlation_rule`, `enricher`, `output_sink`.
- Package format: Python wheel or container image + `sultry-plugin.yaml` manifest (name, version, type, entrypoint, privileged_required, resources_hint).
- Execution isolation: run plugins in separate processes or containers with capability reduction. For Pi, lightweight process isolation and seccomp-like gating.
- API surface: gRPC or HTTP local endpoint with stable v1 contract: `evaluate(event) -> {factors}` for stateless; `on_event(event)` and `flush()` for stateful plugins.

---

**Modularization guidance (limit files to <= 400 lines)**
- **Philosophy:** One concept per file. Keep files small to ease review, LLM analysis, and reduce cognitive load.
- **Rules:**
  - Max 400 logical lines per `.py`, `.json`, `.html` file. (CI enforces approximate line counts ignoring docstrings.)
  - If a module needs more than 400 lines, split by role: `api_*`, `pipeline_*`, `factors_*`, `hopgraph_*`, `db_*`, `tests_*`.
  - Prefer small classes and pure functions; aim for 50–200 LOC units.
  - Group related small files under a package directory (e.g., `core/`, `tier0/`, `tier1/`, `plugins/`).
- **Practical splits to apply to large JanuSec files:**
  - `src/api/app.py` → split to `app_factory.py`, `routes/_*.py` (per domain), `startup_tasks.py`, `middleware/*.py`, `schedulers.py`.
  - `hopgraph` → `hopgraph_core.py`, `persistence.py`, `api_facade.py`, `metrics.py`.
  - `correlation rules` (week1/week2/etc.) → each rule file should only register 8–12 rules; put rule registry & helpers in `rules/registry.py`.
- **CI checks:** add a `check_max_lines.py` script run in pre-commit / CI that warns/blocks files >400 lines and suggests refactor targets.

---

**Tests & evaluation matrix to include in PRD**
Purpose: verify correctness, performance, resilience, security, and ML behavior.

- Unit tests: per-module coverage for ingestion, normalization, factor evaluation, HopGraph operations, DB adapters. (use `pytest`)
- Integration tests: full pipeline from sensor → ingest → verdict; mock external intel feeds.
- E2E honeypot tests: use synthetic attacker flows to exercise canary file access, SSH brute-force, web form exfil.
- Performance tests: latency/throughput benchmarks for Tier0/Tier1/Tier2 paths; expensive: vector search p95/p99, LLM p95/p99.
- Load tests: simulate daily event volumes (1K/day, 10K/day, 100K/day) to validate memory and retention policies.
- Security tests: fuzzing ingest endpoints, plugin sandbox escape checks, signed payload verification tests.
- Model & drift tests: embedding drift (JS divergence), shadow model evaluation, precision/recall for labeled incidents.
- Regression tests: example historic incidents are replayed and expected verdicts asserted.
- Chaos tests: simulate DB outage, Redis outage, and confirm graceful degradation and local buffering behavior.

For each test category include acceptance criteria (e.g., Tier1 p95 < 50ms for 90% of events during 1k/day load).

---

**Factor taxonomy & crosswalk (summary)**
Design: factors are atomic detectors producing `(name, domain, score, confidence, tags, mitigation_hint, mappings)`.

- Domains: `deception`, `network`, `endpoint`, `identity`, `cloud`, `supply_chain`, `application`, `data`.
- Example factors (deception-focused): `honeypot_interaction`, `canary_file_access`, `fake_credential_used`, `tripwire_triggered`.
- Example network factors: `beacon_like_traffic`, `rare_port_usage`, `suspicious_dns_tld`, `nxdomain_spike`.
- Endpoint: `lolbin_detected`, `credential_dump_attempt`, `weird_process_lineage`.

Crosswalk targets (each factor should have zero or more mappings):
- **MITRE ATT&CK**: `technique_ids` list (e.g., `T1078`).
- **STRIDE**: map to threat type(s) (Spoofing, Tampering, Repudiation, Info Disclosure, Denial, Elevation).
- **PASTA**: map to threat scenarios where applicable.
- **Diamond Model**: tag `adversary`, `capability`, `infrastructure`, `victim` where available.
- **Cyber Kill Chain**: stage mapping (Reconnaissance → Weaponization → Delivery → Exploitation → Installation → Command & Control → Actions on Objectives).
- **Compliance controls**: SOC2/ISO/PCI control references where detection supports control (CIS benchmarks, logging/alerting controls).
- **DREAD / Maestro**: optional risk scoring fields to support prioritized triage.

Schema for factor metadata example:
```
{
  "name": "honeypot_interaction",
  "domain": "deception",
  "severity": 0.9,
  "confidence": 0.7,
  "mitre": ["T1590"],
  "stride": ["InfoDisclosure"],
  "kill_chain": ["Reconnaissance"],
  "compliance": ["ISO27001.A.12.4"],
  "dread": {"damage":8, "repro":6}
}
```

Include a `factors_catalog` file in the unpacked folder that enumerates the initial set of 40-80 factors with crosswalks.

---

**Graceful degradation & circuit breaker baselines**
- Circuit breakers to include: memory-based (skip heavy analyses when memory > threshold), cost-based (LLM budget), latency-based (skip slow stages when p95 exceeds threshold).
- Default baseline thresholds (tunable in config):
  - Memory breaker: 75% used → skip Tier2 heavy ops.
  - LLM cost breaker: daily budget default $50 USD → block LLM beyond budget.
  - Latency breaker: p95 threshold 500ms → reduce RAG calls; p95 2s → pause heavy flows.
- Fallback priorities: cached verdicts → Tier1 heuristics → queue for later Tier2 analysis → store raw event for offline processing.
- Circuit breaker actions: exponential backoff, alert to operators, telemetry + reason stored with each ignored event.

---

**Evaluation & acceptance criteria (concise)**
- Functional: ingest normalized events; execute factors and produce verdict JSON with provenance chain.
- Performance: Tier1 p95 < 50ms under 1k/day baseline; caching hit ratio target 80% for 1h window.
- Reliability: local buffer preserves events on network outage; no data loss for 24h outage with default disk size.
- Security: plugin sandbox escapes detected in tests; signed events validated.
- Data quality: less than X% schema validation failures (configurable, e.g., 1%).

---

**Migration & reuse from JanuSec (suggested items to copy/adapt)**
- HopGraph core logic and PPR algorithms (split into core, persistence, facade)
- Factor definitions and taxonomy files (recycle the 40–60 domain-agnostic factors)
- Circuit breaker primitives and FinOps manager
- Baseline/EWMA implementations
- Metrics (Prometheus) and dashboards templates
- Synthetic test corpus & data generators

---

**LLM analysis directive (explicit)**
When analyzing this PRD, produce these artifacts:
1. JSON plan (see `How to use this file`).
2. File-level modularization suggestions: list files to create and files to split, each with estimated LOC.
3. A prioritized 8–12 week roadmap with epics and milestones (MVP, scale, enterprise features).
4. Security & legal gaps checklist.
5. A test matrix mapping tests to CI jobs and resource estimates.

Include recommendations for a CI job that enforces the 400-line rule and produces a modularization report.

---

**Branding note: "Sultry AI"**
- Strengths: memorable, apt for deception/honeypot context.
- Risks: informal/marketing tone may not be enterprise-friendly in some regions. Alternative neutral names: `DecoyAI`, `HoneyGraph`, `Decepta`, `SentinelDecoy`.
- Recommendation: Accept `SultryAI` for open-source and research editions; consider `SultryAI Enterprise` or neutral enterprise product name for paid offerings.

---

**Open questions for product team (to include in PRD)**
- Target daily event volume tiers for v1: what are conservative/expected/peak numbers? (e.g., 1k/10k/100k/day)
- Default retention policy decisions for customers: minimum hot retention and cold archive durations.
- Which third-party threat intel feeds will be default included in community build?
- Legal constraints: any regions that must be excluded due to local laws?
- Plugin trust model: will there be a curated plugin registry with signing, or a community registry without guarantees?

---

**Deliverables in this folder (when unpacked by GitHub)**
- `SultryAI_PRD_PROMPT.md` (this file)
- `examples/` — example events, factor metadata, plugin manifest templates
- `scripts/` — `check_max_lines.py`, `generate_example_events.py`
- `factors_catalog/` — initial factor JSON entries (40–80 items)
- `ci/` — suggested CI job definitions (YAML snippets) to enforce modularization and tests

---

If you want, I will now: (pick one)
1. Create the `examples/` and `scripts/` scaffolding in `sultry_prd/` and commit small helper scripts (line-checker, event generator).
2. Draft the `factors_catalog` JSON with 40 initial factors and their crosswalks.
3. Generate the CI YAML snippet and `check_max_lines.py` stub and add to the folder.

Pick which I should implement next and I'll add the files into `sultry_prd/`.
