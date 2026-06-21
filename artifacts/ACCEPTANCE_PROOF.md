# JanuSec — Acceptance Proof

**Status: ✅ PASSING** — 58 acceptance assertions, generated 2026-06-21 01:14 UTC.

This is the deterministic-correctness evidence behind JanuSec's breach detection,
validated against ground-truth datasets (not LLM-inferred). Regenerate with
`python scripts/acceptance_proof.py`.

## Ground-truth datasets
- **VESPER** — true-positive multi-stage breach (APT29-style on martin.chen)
- **Meridian** — clean positive control (no VESPER leakage)
- **Santos** — noisy / pentest / false-positive resistance

## What every release must satisfy

| Invariant | Guarantee |
|---|---|
| Right actor & verdict | martin.chen -> VALIDATED_BREACH with the OAuth-consent entry point |
| Red herrings suppressed | anna / svc_jenkins / david never graded as confirmed breaches |
| Full kill chain in one campaign | >=5 phases for the actor; red herrings stay <=2 |
| Exfil stitched to actor | cumulative lookalike-destination exfil attaches to the breach |
| Detectors don't go silent | every kill-chain detector fires; NDJSON shadow-shape guarded |
| Narration doesn't fall back | clean-JSON model, <think> stripped, truncation salvaged |
| CEO report populated | a VALIDATED_BREACH yields non-empty kill_chain/stride/maestro/controls |
| HTML export carries CEO sections | Severity Distribution + Top MITRE present |
| LIVE export deterministic | same assessment_id -> identical report data |
| Canonical campaign truth | one Campaign object: actor/kill-chain/IOCs/timeline/confidence |
| Personas render from campaign | all 8 personas ground in the canonical campaign |
| State singleton | one DECISION_CACHE; a recorded breach is visible to the report |

_Result line: `58 passed, 2 skipped, 3753 deselected, 17 warnings in 100.00s (0:01:40)`_
