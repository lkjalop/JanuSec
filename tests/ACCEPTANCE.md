# Golden Acceptance Harness

The single "is the platform still correct end-to-end" gate. Run it before any release
or risky refactor:

```
pytest -m acceptance -p no:cacheprovider -o addopts="" --timeout=600
```

It exists because unit tests pass while the *platform* silently breaks — the failure
modes we keep hitting are integration-level (a detector that stops firing, a breach
verdict dropped from the report, narration falling back). Each of those shipped at some
point with green unit tests. This harness is the net.

## What it asserts (and which file owns it)

| Property | File |
|---|---|
| **Right actor / right verdict** — martin.chen → VALIDATED_BREACH with the OAuth entry point | `test_ground_truth_gate.py` |
| **Red herrings suppressed** — anna/svc_jenkins/david never graded as confirmed breaches | `test_ground_truth_gate.py` |
| **Kill chain complete in one campaign** — ≥5 phases for the actor; herrings stay ≤1–2 | `test_ground_truth_gate.py` |
| **Exfil stitches to the actor** — cumulative lookalike-destination exfil attaches to martin | `test_ground_truth_gate.py` |
| **Detectors don't go silent** — every kill-chain detector fires on VESPER; NDJSON shadow-shape guarded | `test_detector_firing_coverage.py` |
| **Narration doesn't fall back** — clean-JSON model, `<think>` stripped, truncation salvaged | `test_narrator_robustness.py` |
| **CEO report populated** — a VALIDATED_BREACH yields non-empty kill_chain/stride/maestro/controls/scenarios | `test_report_ceo_contract.py` |
| **HTML export carries CEO sections** — Severity Distribution + Top MITRE present in the HTML | `test_report_ceo_contract.py` |
| **LIVE export is deterministic** — same `assessment_id` → identical report data | `test_report_ceo_contract.py` |

## Datasets (golden benchmarks)

- **VESPER** — true-positive multi-stage breach (APT29-style on martin.chen).
- **Meridian** — clean positive control / no VESPER leakage.
- **Santos** — noisy / pentest / false-positive resistance.

Dataset-backed gates skip cleanly when `dump/test files/{Vesper,Meridian,Santos}` is
absent (CI without the large fixtures). The CEO-report + detector-shape + narration
checks run everywhere.

## Adding to the harness

Mark the test module with `pytestmark = pytest.mark.acceptance`. New high-value
end-to-end invariants belong here — if a bug could ship green at the unit level but
break the breach→report path, it needs an acceptance assertion.
