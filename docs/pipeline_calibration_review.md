# 21-Stage CSV Deep Analyze Pipeline – Reality Check & Calibration Plan

**Audience:** Opus 4.5 engineering crew (pipeline owners, scoring maintainers, UI/LLM Integrations)  
**Source data:** `src/core/event_pipeline/*`, Tier 1/Tier 2 UI flows (`frontend/static/csv_*.html`), Cyberstash XDR log drops from recent uploads.  
**Purpose:** Document how the current “21-step” enrichment pipeline *actually* behaves, where calibration drifts originate, why Tier‑1/Tier‑2 summaries are mistrusted, and which input factors are causing noisy “UNKNOWN” outputs so we can hand a clean fix list to Opus 4.5.

---

## 1. Current Pipeline Anatomy
Location: `src/core/event_pipeline/pipeline.py` (driver) + `src/core/event_pipeline/stages/*.py` (stage runners).

| # | Stage (code name) | Module | What it’s supposed to do | Notes |
|---|-------------------|--------|--------------------------|-------|
| 1 | `baseline` | `stages/primitives.py` | Normalize fields, ingest avScore/threatWeight, seed verdict/confidence. | Adds first confidence delta; no negative weighting. |
| 2 | `regex` | `stages/primitives.py` | Match file/process/network strings against curated Yara/regex heuristics. | Emits `regex_match_*` factors. |
| 3 | `parent_child` | `stages/primitives.py` | Analyze process lineage, spawn stacks. | Emits `suspicious_parent_child_pair` when heuristics match. |
| 4 | `endpoint` | `stages/primitives.py` | Endpoint-specific enrich (LOLBin detection, temp-path heuristics). | Source of `unsigned_sensitive_path`, `temp_dropper`. |
| 5 | `auth_burst` | `stages/primitives.py` | Auth anomaly detector for credential spray. | Often skipped for file-only events (no auth telemetry). |
| 6 | `identity` | `stages/identity.py` | Identity & role baseline lookups. | Missing host/user ⇒ outputs `identity_unknown`. |
| 7 | `graph` | `stages/primitives.py` | Light HopGraph hooks (write row for later correlation). | Adds timings but not much scoring. |
| 8 | `adaptive_pre` | `stages/primitives.py` | Tenant override gate, baseline blending heuristics. | Another additive confidence bump. |
| 9 | `packet_summary` | `stages/primitives.py` | Parse packet summaries (JA3, SNI, ASN). | Needs net fields; Cyberstash uploads seldom include them. |
| 10 | `sbom_exec` | `stages/sbom.py` | Map binaries to SBOM components. | Without SBOM context defaults to “unknown component”. |
| 11 | `sbom_vuln` | `stages/sbom.py` | Cross SBOM → CVE. | Skipped when hashes not in SBOM repo. |
| 12 | `ebpf_analysis` | `stages/ebpf_analysis.py` | eBPF runtime signals (kernel tamper, syscalls). | No eBPF feed in CSV drop ⇒ no factors. |
| 13 | `cert_analysis` | `stages/__init__.py` wrapper | Validates cert metadata. | Doesn’t see `signer_subject` in Cyberstash CSV ⇒ outputs `cert_unknown`. |
| 14 | `http_header` | `stages/__init__.py` wrapper | HTTP header heuristics. | Needs http fields, rarely present. |
| 15 | `beacon` (heavy) | `stages/network.py` | Dwell/beacon detection. | Frequently skipped via confidence gate. |
| 16 | `egress` (heavy) | `stages/network.py` | Egress anomaly detection. | Skipped under load or missing net fields. |
| 17 | `domain_novelty` (heavy) | `stages/network.py` | Domain rarity scoring. | Needs domain/host; Cyberstash logs seldom include. |
| 18 | `rare_token` | `stages/network.py` | Rare token detection (headers/paths). | Typically emits `novel_global` if file hash unseen. |
| 19 | `hunt_lanes` | `stages/advanced.py` | Lane-specific detections (process lineage, JA3). | Writes `lane_process_lineage:*` etc. |
| 20 | `correlation` | `stages/advanced.py` | Multi-event and multi-signal combination. | Requires session context; CSV singletons rarely correlate → returns synthetic summary. |
| 21 | `quality_filter` | `stages/advanced.py` | Prune low-quality factors. | Weak – mostly passes everything through. |
| 22 | `mapping` | `stages/advanced.py` | Canonical field mapping stats. | Adds `mapping_semantics_*`. |
| 23 | `cluster_dedupe` | `stages/advanced.py` | Deduplicate near-identical events. | Minimal effect if we ingest unique rows only. |
| 24 | `coverage_tracker` | `stages/advanced.py` | Track evidence coverage per tenant. | Doesn’t feed back into scoring. |
| 25 | `embedding` | `stages/advanced.py` | Embedding-based anomaly detection / SSE gating. | Often skipped when embeddings disabled. |

**Key takeaway:** even though “21-step pipeline” is our marketing line, the code currently runs up to 25 sequential stages. Most of them add positive confidence deltas; almost none subtract when trust signals are present.

---

## 2. Factors Driving Tier‑1 Alerts
Dissected from `src/artifact/factors.py`, `core/correlation/factor_constants.py`, and auto‑LLM prompt scaffolding.

| Factor | Source Stage | Meaning / when it fires |
|--------|--------------|-------------------------|
| `novel_global` | `rare_token_stage` | Hash not seen in enterprise baseline. |
| `temp_dropper_path` | `endpoint_stage` | Executable landed in temp / crash kit folder. |
| `unsigned_sensitive_path` | `endpoint_stage` | Unsigned binary executed from protected path. |
| `lane_process_lineage:*` | `hunt_lanes_stage` | Off-normal parent/child spawn (e.g., Office → PowerShell). |
| `corr_*` constants | `correlation_stage` | Multi-signal combos (beacon + rare JA3, etc.). |
| `asn_rarity_high` / `asn_kevsuspect` | `domain_novelty_stage` | Peers on rare ASN or KEV candidate. |
| `signed_transition` | `parent_child_stage` | Signed parent launching unsigned child. |
| `threatWeight`, `avPositives` | Baseline ingestion | Raw numeric fields from CSV. |
| `identity_unknown`, `host_unknown` | `identity_stage` | Missing user/host context. |
| `cert_unknown` | `cert_analysis` | Signer/timestamp absent. |
| `coverage_low` | `coverage_tracker` | Evidence coverage below thresholds. |

Because cyberstash CSVs typically omit parent process, signer, SBOM linkages, and network metadata, the “unknown” variants light up on almost every row. These do **not** subtract confidence; instead they simply leave the positive factors untouched. Hence 135/500 rows end up `SUSPICIOUS` purely due to `novel_global + temp_dropper + avPositives>0`.

---

## 3. Why Tier‑1 Output Is Distrusted
Example: `fsagentcrashstatusupdater.exe` row (hash `6307545a…`).

* Tier‑1 verdict: `SUSPICIOUS • DREAD 9 • Confidence 55%`.
* Signals: only `novel_global` and duplicate “hash not seen” explanation.
* Flags: `flagName="Verified Good"` but `suspicious=true`, `whitelist=false` ⇒ contradictory state.
* MITRE mapping: `T1059.003 / T1105 / T1055` even though no command line, network events, or injection logs exist. Explain JSON shows `source: "client-synth"` meaning the reason string is a synthetic fallback, not real telemetry.
* Missing critical context: no signer, no parent, no network peers, host/user set to `unknown` (due to Cyberstash CSV lacking those columns).

Result: analysts ignore the DREAD/MITRE output because it reads like boilerplate. Escalations get second-guessed, while actual high-signal detections drown in the backlog of novelty-only alerts.

---

## 4. Tier‑2 Summary Issues
Even after the UI refresh (`frontend/static/csv_deep_analysis.html`), the data still originates from the same weak pipeline outputs:

* Tier‑2 call `/api/v1/csv/tier2_investigate` reuses Tier‑1 payload and adds LLM sugar. When Tier‑1 lacked host/user/signer, Tier‑2 cards repeat “Unknown host/user” across Executive Summary, Domain gating, Knowledge Gaps.
* When pipeline correlation can’t load attack graph context, Tier‑2 goes to cache or returns “Tier 2 returned no summary.” That’s frequent because cyberstash single rows can’t build HopGraph sessions (missing session IDs, baseline data).
* “Why Flagged” + “Key Evidence” still cite the same single factor (`novel_global`). Without pipeline calibration, Tier‑2 narratives remain speculative, so analysts lose trust.

---

## 5. Root Causes Requiring Calibration
1. **Additive confidence with no subtraction:** `_blend()` always adds incoming deltas (baseline weight ≥1). Allowlist hits append factors but don’t reduce existing score.
2. **Trust signals ignored:** A valid signature, known vendor, or analyst `Verified Good` flag does not cap severity/confidence.
3. **Synthetic explanations misrepresented:** When correlation fails, UI still displays MITRE tactics as if observed. Needs “Suspected” label or removal.
4. **Data sparsity from Cyberstash XDR:** Logs miss host, user, signer, parent, network metadata. Pipeline treats missing context as neutral, yet UI reads it as `unknown`, leading to low analyst confidence.
5. **Tier segmentation absent:** All detections, even novelty-only, enter Tier‑1 queue. No gating to keep “investigate later” vs “act now” separate.

---

## 6. Examples of Calibration Failures
| Scenario | What pipeline does today | Why it’s wrong |
|----------|-------------------------|----------------|
| `Verified Good` row (analyst override) | Still shows SUSPICIOUS, DREAD 9, MITRE tags. | Verified rows should be suppressed or require contradictory telemetry before re-alerting. |
| Signed vendor binary in temp folder | `temp_dropper_path + novel_global` yields high risk. | Need signer validation to reduce severity when vendor is trusted (Freshworks), and treat temp crash bundles as lower impact. |
| AV positives = 4/74 | Adds threatWeight 7 + DREAD bump. | Low-consensus hits should be “weak signal”; without additional evidence, remain “Monitor”. |
| Missing host/user fields | UI prints `Host: unknown host • User: unknown user`. | Should trigger ingestion fix (map Cyberstash columns) or degrade severity to “needs enrichment”. |

---

## 7. Recommendations for Opus 4.5
1. **Introduce negative weighting:** Extend `_blend()` to subtract when allowlist, valid signer, or analyst feedback exists. Cap final confidence when `flagName` indicates benign.
2. **Trust gating for novelty:** Require at least one behavioral or network factor (LOLBin parent, beacon hit, credential theft) before escalating `novel_global` events to Tier‑1. Otherwise push to a “monitor later” queue.
3. **Evidence-backed MITRE mapping:** Only label MITRE techniques when the corresponding stage contributed a factor. If explanation is `client-synth`, display “Not observed (placeholder)” in UI.
4. **Cyberstash mapping fixes:** Update ingest adapters (`src/api/csv_handler.py`) to parse known Cyberstash column headers (host, user, signer, parent, detection source). Until available, mark rows as `Needs enrichment` instead of `SUSPICIOUS`.
5. **Tier routing:** Add pipeline metadata `severity_band` (High/Medium/Low) and `confidence_band`. Tier‑1 UI should show only High/High-Med combos. Tier‑2 auto-run only for those rows; others stay in backlog.
6. **Expose factor provenance:** In Tier‑1/Tier‑2 panels, list which stage produced each factor (`novel_global` from rare_token, `lane_process_lineage` from Hunt Lane). Analysts can then trust or dispute specific signals.
7. **LLM summary guardrails:** When payload lacks host/user/signer, Tier‑2 summary should explicitly say “Telemetry missing – request logs” instead of rephrasing synthetic content.

---

## 8. Unknown/Null Fields Cheat Sheet
| UI field | Backend origin | Why it’s “unknown” | Fix path |
|----------|----------------|--------------------|----------|
| Host/User | `currentRow.host`, `currentRow.user` | Cyberstash CSV doesn’t populate `host`/`user` columns; pipeline defaults to `unknown`. | Update CSV importer to map Cyberstash `device_hostname`, `userPrincipalName`, or require aggregator to provide them. |
| Signer | `payload.cert.subject` | CSV lacks `signer_subject`/`signature_status`. | Extend Cyberstash export or run sigcheck during ingestion. |
| MITRE evidence | `payload.ai_reasoning.supporting_evidence` | Synthetic explain due to missing event_id (client-synth). | Ensure `event_id` from pipeline is passed to `/api/v1/risk/{id}/explain`, or hide MITRE tags when synthetic. |
| Attack Graph | `/api/v1/graph/session/build` | Single Cyberstash rows have no `session_ids`. | Buffer multiple rows per upload before invoking HopGraph, or degrade UI state to “Graph not available for single rows”. |

---

## 9. Closing Summary
*The 21-stage pipeline isn’t broken because of missing code – it’s miscalibrated.* Additive scoring plus sparse telemetry means Tier‑1/Tier‑2 surfaces show confident narratives with almost no evidence. Analysts see “SUSPICIOUS • DREAD 9” with the same single factor repeated, so they stop trusting the UI.

Fixing this requires feeding better context from Cyberstash XDR (host, user, signer, parent), subtracting confidence when trust signals exist, and gating novelty-only alerts away from Tier‑1. Until those steps ship, both tiers should label these alerts “Needs enrichment – telemetry incomplete” to avoid exhausting the SOC with false positives.

This document should give Opus 4.5 exact reference points (files, stages, factor names) to start patching calibration logic, ingest mappings, and UI messaging. Refer back to the tables above during implementation reviews so we can finally deliver a Tier‑1 verdict that matches the real evidence footprint.  

— Prepared for Opus 4.5 remediation sprint
