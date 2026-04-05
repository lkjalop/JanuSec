Endpoint Scoring Environment Variables

This document lists environment variables used to tune endpoint malware composite scoring.

- `SCORING_RARE_BONUS` (float, default 0.03): per-rare-lineage-event bonus added to base score.
- `SCORING_RARE_MAX` (float, default 0.15): cap for total rare-event bonus.
- `SCORING_C2_BONUS` (float, default 0.08): bonus when any network event is marked as known C2.
- `SCORING_BURST_FACTOR` (float, default 0.01): per-burst multiplier used to compute burst bonus.
- `SCORING_BURST_MAX` (float, default 0.12): cap for the burst bonus.
- `SCORING_SYNERGY_BONUS` (float, default 0.05): bonus applied when multi-domain factors (registry/process/injection/network) co-occur.

Notes:
- Scores are normalized and capped at 1.0.
- Lower `SCORING_SYNERGY_BONUS` or raising the synergy activation threshold reduces false positives for multi-domain combinations.
- Use these variables for quick tuning in dev/staging without code changes.

Example (Windows PowerShell):

```powershell
$env:SCORING_RARE_BONUS='0.05'
$env:SCORING_C2_BONUS='0.12'
```
