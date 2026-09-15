# Extensive Threat Validation and Metrics

## Purpose
This document provides an extensible and repeatable framework for validating the platform’s ability to discriminate benign from suspicious to malicious activity, escalate appropriately, correlate context, and generate analyst-ready outcomes. It now incorporates:

- Multi-tiered scenario catalog (benign → gray → confirmed malicious)
- Formal pass/fail gates and confidence bands
- Expanded metrics (coverage, enrichment yield, MTTA/MTTR proxies, correlation lift, severity-weighted precision)
- Validation of escalation pathways and suppression logic
- Mapping to CVE references, MITRE ATT&CK techniques, STRIDE threat categories, and representative compliance controls (e.g., CIS, NIST 800-53 families) to support governance and audit narratives
- Two-page executive report template for stakeholder consumption

Use this as a playbook for automated runs (LLM-assisted or scripted) and as a source artifact for audit & readiness reviews.

---

## 1. Scenario Catalog
Scenarios are grouped by Intent Tier and mapped where possible to ATT&CK/STRIDE. Each scenario should have: input events, expected detections, suppression expectations, escalation target, and artifacts generated.

### 1.1 Benign / Low Suspicion (Should NOT Alert)
- Normal user logins (business hours) – ATT&CK: n/a – STRIDE: n/a
- Routine file reads of public shares – n/a
- Developer pulling git repository – (T1071 context neutral) – ensure suppression
- Scheduled OS patch process (service account activity) – ensure service-account allowlist honored
- Internal network scan from approved vulnerability scanner IP – baseline allow & tag

### 1.2 Gray / Medium Suspicion (Should Alert w/ Medium Severity)
- Off-hours interactive login from unusual geo – ATT&CK T1078 (Valid Accounts)
- Access to sensitive finance directory after privilege change – (T1078 + T1087)
- Lateral movement pivot attempt (new correlation rule) – (T1021, T1047) – Expect correlation `corr_lateral_pivot_possible`
- Excessive authentication failures followed by success – (T1110)
- Suspicious PowerShell encoded command (but incomplete chain) – (T1059.001) – Should raise but not critical unless chained

### 1.3 High / Malicious (Must Alert & Escalate)
- Simulated data exfil (large outbound volume + rare destination) – (T1041)
- Privilege escalation event (e.g., token impersonation) – (T1134)
- C2 beacon pattern (interval jitter + known infra IOC) – (T1071.001)
- Credential dumping attempt signature – (T1003)
- Multi-stage chain: Phish → Initial execution → Lateral movement → Exfil (compound scenario for correlation lift measurement)

### 1.4 Failure & Stress / Adversarial Robustness
- Log flood of benign-like events (ensure rate limiting not degrading precision)
- Mixed benign + single embedded malicious event (needle detection test)
- Delayed event arrival / out-of-order timestamps (resilience of sliding windows)
- Duplicate event replay (idempotency & dedupe correctness)

---

## 2. Pass / Fail & Confidence Bands

| Tier | Primary Goal | Alert Expectation | FP Threshold | Miss Threshold (FN) | Confidence Band (Precision) | Escalation SLA Proxy* |
|------|--------------|------------------|-------------|---------------------|-----------------------------|----------------------|
| Benign | Suppress | None (<= tolerance) | <= 1.5% of benign corpus | n/a | >= 0.985 on suppression precision | n/a |
| Gray | Detect & Triage | >= 90% recall | <= 8% | <= 10% | Precision >= 0.75 | Triage queue mark within X batch |
| High | Immediate Escalation | >= 98% recall | <= 5% | <= 2% | Precision >= 0.90 | Escalation flag same batch |
| Compound Chain | Correlate | Correlation present | n/a | n/a | Correlation lift > 1.3 vs singletons | Escalation aggregated |

*SLA Proxy: Until full MTTA (Mean Time To Acknowledge) instrumentation exists, use “batches elapsed until escalation artifact produced” as a proxy.

Failure Conditions (Hard Fail):
- Any high-severity scenario not producing an alert in its run window
- Benign suppression precision < 0.97 in two consecutive runs
- Correlation rule produces > 10% false correlations across mixed dataset
- Sliding window precision drift > 15% vs prior 7-day average (indicates calibration regression)

Soft Fail (Warning):
- Gray tier recall between 80–89%
- Parallel speedup < 1.3x vs sequential for >3 consecutive runs (performance regression)
- Batch latency p95 > target threshold (define e.g., 500 ms)

---

## 3. Metric Inventory
Core Metrics:
- Precision (overall, tiered, severity-weighted)
- Recall (by scenario class)
- False Positive Rate (FPR) per 1,000 benign events
- False Negative Count (missed mandatory detections)
- Correlation Lift: (Alerts after correlation) / (Base alerts pre-correlation)
- Sliding Window Stability: variance of precision over last N windows
- Batch Latency: p50, p95, max
- Parallel Speedup: sequential_duration / parallel_duration
- Alert Enrichment Yield: % alerts with attached context (user, host, geo, process lineage)
- Escalation Path Reliability: % of high alerts appearing in escalation queue object
- Dedupe Efficiency: (raw suspicious events)/(final distinct alerts)
- Suppression Accuracy: (suppressed events correctly benign)/(total suppressed)

Extended/Optional Metrics:
- MTTA Proxy (batches until escalation)
- Coverage Ratio: scenarios with passing status / total defined
- Drift Indicators: distribution shift flags from benign corpus vs historical baseline

---

## 4. Execution Workflow
1. Generate / refresh benign corpus: `scripts/generate_benign_corpus.py --count 50000 --output data/benign.jsonl`
2. Run low-tier suppression validation: feed corpus, record suppression precision.
3. Execute individual playbooks (A1–A5 + new chain scenario) via `scripts/run_playbook.py --playbook playbooks/A3_lateral.yaml` (example).
4. Combine mixed dataset (benign + injected malicious ratio e.g., 5000:25) to evaluate needle detection.
5. Run FP & severity eval: `scripts/fp_reduction_eval.py --alerts out/alerts.jsonl --ground-truth data/labels.jsonl`.
6. Scrape Prometheus endpoint (e.g., `http://localhost:8000/metrics`) to collect latency and speedup metrics.
7. Compute correlation lift by comparing pre- vs post-correlation alert counts (export debug flag if available).
8. Produce executive report (fill template) – automated via LLM prompt referencing metrics JSON export.

Data Artifacts Suggested:
| Artifact | Purpose | Format |
|----------|---------|--------|
| benign.jsonl | FP baseline | JSON Lines events |
| playbook_*.jsonl | Scenario events | JSON Lines |
| alerts_raw.jsonl | Raw alerts pre-correlation | JSON Lines |
| alerts_final.jsonl | Post-correlation / enriched | JSON Lines |
| metrics_summary.json | Aggregated numeric metrics | JSON |
| run_manifest.yaml | Parameter provenance | YAML |

---

## 5. False Positive & Failure Test Battery
- Service Account Noise: simulate repeated service logons; ensure suppression rules apply.
- Credential Stuffing Simulation: large auth failure rates; confirm only threshold-crossing aggregated alert emitted.
- Benign PowerShell Automation: ensure encoded-but-approved script signatures are not flagged.
- Bulk File Copy (Internal Share): ensure size threshold logic not misfiring on internal-only movement.
- Replay Attacks: feed duplicate event IDs and confirm dedupe ratio improvement.
- Out-of-Order Delivery: shuffle timestamps; ensure sliding window precision not collapsing (>0.9 retained).
- Rate Spike: 10x event ingestion burst—monitor latency p95 stays within SLO.

---

## 6. Escalation & Triage Validation
Objectives:
- High-tier alerts appear in escalation queue structure within same processing batch.
- Gray-tier alerts routed to triage list with appropriate confidence score.
- Enrichment fields present: `user`, `host`, `geo`, `process_chain` (if applicable) ≥ 90% of escalated items.
- Suppressed events never appear in analyst queues.

Test Method:
1. Trigger known high severity scenario.
2. Query escalation endpoint / data structure.
3. Validate presence + enrichment completeness.
4. Record batch index difference between event ingestion and escalation artifact.

Pass Conditions:
- 100% of high severity test alerts escalated.
- Enrichment completeness ≥ target threshold.

---

## 7. Threat Model Mapping (CVE / MITRE / STRIDE / Compliance)

### 7.1 MITRE ATT&CK Mapping
Maintain a mapping table (excerpt):
| Scenario | Technique(s) | Detection Source | Correlation Dependency |
|----------|--------------|------------------|------------------------|
| Lateral pivot | T1021, T1047 | Auth + process events | Host adjacency graph |
| Data Exfil | T1041 | Netflow + file access | Volume + rare dest model |
| Priv Esc | T1134 | OS security logs | Privilege change event chain |

### 7.2 CVE Referencing
While behavioral detections are technique-focused, link exploited software or privilege escalation vectors to recent CVEs when context (process, binary hash) matches known vulnerable component. Maintain optional `cve_context` field in enrichment.

### 7.3 STRIDE Classification
For each alert, store inferred STRIDE category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) to support threat model coverage metrics.

### 7.4 Compliance Control Alignment
| Framework | Relevant Control | Detection Contribution |
|-----------|------------------|------------------------|
| CIS v8 | 5, 6, 8 | Account monitoring, audit log review |
| NIST 800-53 | AU-6, IR-4, AC-2 | Audit review, incident response initiation |
| ISO 27001 | A.16, A.12 | Incident mgmt, operations security |

Include coverage ratio: (# controls materially supported)/(scope controls).

---

## 8. Data Integrity & Provenance Checks
- Hash manifest for each artifact set (SHA-256) – store in `run_manifest.yaml`.
- Verify event count conservation pre/post correlation except for expected suppression & dedupe.
- Maintain environment variables provenance (parallel mode, window size) for reproducibility.

---

## 9. Two-Page Executive Report Template

### Page 1 – Outcomes Overview
Section: Snapshot Metrics
| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Coverage Ratio | __% | >= __% | Pass/Watch/Fail |
| High Recall | __% | >= 98% | |
| Gray Recall | __% | >= 90% | |
| Suppression Precision | __% | >= 98.5% | |
| Severity-Weighted Precision | __% | >= __% | |
| FP per 1k Benign | __ | <= __ | |
| Correlation Lift | __x | >= 1.3x | |
| Parallel Speedup | __x | >= 1.3x | |
| Batch Latency p95 | __ ms | <= __ ms | |

Narrative Summary:
- Top Strengths: [...]
- Key Gaps: [...]
- Risk of Inaction (30–60 days): [...]

Section: Threat Coverage Mapping Highlights
- Techniques newly covered this period
- Notable CVE-linked behaviors observed
- STRIDE category distribution (pie or table)

### Page 2 – Deep Dive & Recommendations
Section: False Positive & Drift Analysis
- FP root cause categories (config gap, enrichment miss, model threshold) with counts
- Drift indicators (if any) vs baseline benign corpus

Section: Escalation & Workflow Efficiency
- High severity escalation SLA proxy performance
- Enrichment completeness %
- Dedupe efficiency improvement vs last run

Section: Control & Framework Alignment
- Coverage deltas vs last report (CIS, NIST)
- Pending control gaps slated for next sprint

Section: Priority Actions (Next 2 Sprints)
| Priority | Action | Owner | ETA | Expected Impact |
|----------|--------|-------|-----|-----------------|
| P1 | Improve gray recall for lateral movement | Platform | __ | +8% recall |
| P2 | Add exfil anomaly lane | Detection Eng | __ | Coverage +5% |

Appendix Hooks (Optional)
- Run manifest hash
- Artifact index
- Methodology note (how metrics computed)

---

## 10. Automation Prompt Template (For LLM Execution)
Provide the following context to an automation agent (e.g., Claude) to generate a fresh report:

"""
Goal: Execute full threat validation cycle and produce executive report.
Steps:
1. Generate benign corpus (count=50000).
2. Run all playbooks (A1–A5 + chain scenario) capturing raw and final alerts.
3. Export metrics JSON (precision, recall, FP rate, lift, latency, speedup).
4. Populate executive template fields.
5. Summarize strengths, gaps, priority actions.
Deliver: Two-page markdown using template in section 9.
"""

---

## 11. How to Use This Document
1. Define any new scenarios – append to Section 1 with IDs.
2. Run automated pipeline; collect artifacts enumerated in Section 4.
3. Evaluate pass/fail gates in Section 2.
4. Generate executive report (Section 9 template).
5. Log deltas & regression notes for audit continuity.

---

## 12. References
- `docs/validation_runbook.md`
- `docs/test_matrix.md`
- `docs/comprehensive_testing_roadmap.md`
- MITRE ATT&CK (https://attack.mitre.org/)
- NIST 800-53 Rev5
- CIS Controls v8

---

*This document can be iteratively expanded; treat sections as living controls evidence.*
