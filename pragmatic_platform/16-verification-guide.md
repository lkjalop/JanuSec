# 16. Artifact Sidecar Verification & Trust Guide
Status: Draft
Last Updated: 2025-09-23

## 1. Purpose
Define reproducible steps to verify that artifact risk outputs, factor listings, and technique mappings are deterministic, grounded in code, and not hallucinated.

## 2. Inputs & Snapshots
| Artifact | Path | Action |
|----------|------|--------|
| Excel Source 1 | dump/cybstash csv1.xlsx | Compute SHA-256, store in log |
| Excel Source 2 | dump/Cyberstash_csv2.xlsx | Compute SHA-256 |
| Raw Parsed JSON | dump/debug/input_rows.json | Save pre-ingestion normalized records |
| Generated Report | dump/artifact_reports/latest.json | Produced by pipeline |

## 3. Hash Capturing (Example Commands)
```python
import hashlib, json, pathlib
files = ["dump/cybstash csv1.xlsx","dump/Cyberstash_csv2.xlsx"]
print({f: hashlib.sha256(open(f,'rb').read()).hexdigest() for f in files})
```
Store output in `dump/debug/source_hashes.json`.

## 4. Field Normalization Validation
1. Load `input_rows.json`.
2. Assert each record has `name` or infer from path, plus at least one of `path`/`sha256`.
3. If `artifact_type` absent, extension inference must match rule set in code.

## 5. Factor Integrity Check
Extract all factors from `latest.json`:
```python
import json
rep=json.load(open('dump/artifact_reports/latest.json'))
reported=set(f for item in rep['top_risky'] for f in item['factors'])
print('Reported factors:',sorted(reported))
```
Cross-check each factor string exists in `artifact/factors.py` source (grep or programmatic parse). If any mismatch: flag.

## 6. Technique Mapping Validation
1. Load mitre techniques from each artifact (`item['mitre']`).
2. In `artifact/technique_mapping.py`, verify they appear as mapped output values.
3. For new techniques not in mapping file: investigate factor seeds.

## 7. Risk Recalculation Spot Test
Recompute risk for 1–2 artifacts:
```python
from artifact.risk import synthesize_risk  # adjust import if needed
# Provide synthetic FactorContribution list mirroring actual artifact factors
# Compare returned risk to serialized report risk (allow rounding diff < 0.5)
```

## 8. Reputation Influence Verification
If `ARTIFACT_REPUTATION_ENABLED=false`, verify no reputation factor tokens appear or their deltas are zeroed. Enable and re-run batch: confirm presence of `reputation` / `vt_` related factor(s) and risk change.

## 9. Rarity & Propagation Validation
Inspect `artifact_prevalence.json` after second batch ingestion:
- First batch artifact → should appear with count=1.
- Second batch repeated artifact → count increments; rarity classification transitions per design thresholds.

## 10. MITRE Delta Determinism
Consecutive runs without new factors: `mitre_delta` should be empty or only reflect frequency increments (delta list stable except counts). Introduce a new macro file → expect new techniques appended.

## 11. Override Persistence Test
1. POST override for artifact ID.
2. Fetch latest report; confirm verdict changed or override recognized in feedback store (depending on design; adjust serializer if needed).
3. Re-run batch ingestion with same artifact → verify override not lost (if override intended to persist across batches).

## 12. Logging / Audit Suggestions
Add structured log on batch completion:
```text
artifact_batch_complete batch_id=... count=... malicious=... suspicious=... rare=... techniques=...
```
Retain last N logs for audit.

## 13. Automated Test Skeleton (Future)
- `tests/test_factor_strings.py` ensures all factor names in report are defined in factor extraction logic.
- `tests/test_mitre_mapping_sync.py` ensures each reported technique is declared in mapping file.
- `tests/test_risk_replay.py` recomputes random sample risk.

## 14. Non-Hallucination Principles Applied
| Principle | Applied Mechanism |
|-----------|-------------------|
| Deterministic Factor Names | Hardcoded extraction functions; no free-form generation |
| Bounded LLM Influence | Ambiguity gating & delta cap (if enabled) |
| Persisted State | Prevalence JSON for stable rarity classification |
| Verifiable Snapshots | Raw input & output stored for diffing |

## 15. Checklist
- [ ] Source file hashes recorded
- [ ] Parsed input snapshot saved
- [ ] Report factors cross-checked
- [ ] Techniques mapped & verified
- [ ] Spot risk replay successful
- [ ] Reputation toggle effect confirmed
- [ ] Rarity state verified across batches
- [ ] Override persistence validated

---
End of Verification Guide
