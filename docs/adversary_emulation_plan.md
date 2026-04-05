# Adversary Emulation Plan (Phase 1)

Purpose: Provide structured, repeatable evaluation of detection coverage, latency, precision, and false positive suppression across representative multi-stage attack scenarios prior to pilot.

## Objectives
- Quantify coverage (%) of defined adversary scenarios.
- Measure Mean Time To First Detection (MTTD) per scenario.
- Attribute which lanes / correlation rules contribute to detection.
- Identify detection gaps (uncovered tactics) for roadmap.
- Provide executive summary metrics: Coverage, MTTD, FP Rate, Correlation Uplift.

## Scenario Matrix (Initial Set A1–A8)
| ID | Tactics (MITRE) | Description | Key Signals Expected | Current Coverage Expectation |
|----|-----------------|-------------|----------------------|------------------------------|
| A1 | Execution, Lateral Movement | Pass-the-hash pivot, remote process spawn sequence | lane_proc_parent_chain, lane_ja3_rare (if TLS pivot), corr_lateral_pivot_possible | Partial (need new corr rule) |
| A2 | Execution, Defense Evasion, Discovery | LOLBin (certutil) download + staging | process lineage factor (generic), missing dedicated LOLBin heuristics | Low |
| A3 | Credential Access, Priv Esc, Lateral Movement | Service account abnormal login + privilege escalation chain | auth burst (if enabled), lineage factor, correlation combo | Partial |
| A4 | Discovery, Collection, Exfiltration | Slow data exfil via HTTPS in small chunks | (GAP) need exfil volume lane | None |
| A5 | Command & Control | Jittered beacon with rare JA3 hash | lane_ja3_rare | Good |
| A6 | Persistence, Defense Evasion | Scheduled task + living-off-the-land binary | (GAP) persistence lane absent | None |
| A7 | Credential Access | Brute-force then success (auth burst) | auth_burst factors | Good |
| A8 | Collection, Exfiltration | DNS tunneling (TXT exfil) | (GAP) DNS entropy / tunneling lane missing | None |

## Metrics
- Coverage = detected_scenarios / total_scenarios.
- MTTD = first_detection_timestamp - scenario_start.
- Correlation Uplift = scenarios_with_correlation_primary / scenarios_with_lane_only.
- FP Rate (Benign Corpora) = factors_on_benign / benign_events.
- Precision (Sliding Window) = TP_factors / (TP_factors + FP_factors) over last N events (N configurable).

## Data Artifacts
- `playbooks/*.yaml` scenario definitions.
- `metrics/emulation/run_<timestamp>.json` full trace.
- `validation_test_results.md` appended summary.

## Execution Workflow
1. Generate or curate benign background event stream (noise profile).
2. Inject scenario events per playbook timing offsets.
3. Capture pipeline decisions (factors, timings) via API and DB queries.
4. Compute metrics + export run artifact.
5. Append summary to validation report.

## Gap Remediation Roadmap (Derived)
Priority 1: Lateral pivot correlation rule (A1)  
Priority 2: Exfil volume heuristic lane (A4)  
Priority 3: Beacon periodicity / jitter scoring (refine A5 for FP control)  
Priority 4: LOLBin / command-line heuristic lane (A2, A6)  
Priority 5: DNS tunneling detection lane (A8)  
Priority 6: Persistence scheduling detection (A6)  

## Threshold Targets (Pilot Readiness)
- Coverage >= 55% (Phase 1) with explicit documented gaps.
- MTTD median < 30s simulated.
- FP Rate reduction >= 30% vs pre-suppression baseline.
- Correlation contributes to >= 1 high-confidence reclassification.
- No tenant leakage.

## Next Steps
- Implement harness skeleton and first playbook (A1).
- Integrate sliding precision metrics.
- Produce first partial run (A1 + benign baseline) to validate pipeline instrumentation.
