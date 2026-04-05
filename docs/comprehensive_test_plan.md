# Comprehensive Test Plan

Version: 2025-09-24
Target System: Pragmatic Security Threat Sifting Platform (JanuSec)

## 1. Objectives
Provide an auditable, non-lazy, end-to-end validation corpus covering:
- Ingestion → Pipeline → Decision → Explanation → Notification
- Endpoint Hunter behavioral detections (rarity stabilization, burst, persistence, signed mismatch)
- Artifact Scanner (static, macro/script, LOLBin/tunneling, reputation, ambiguity → refinement, escalation chain)
- SBOM vulnerability factor mapping and cap scaling
- File batch triage, custody hashing, correlation & auto attachment
- Governance readiness (escalation placeholder; approval future scope)
- Metrics & integrity (Prometheus counters presence, custody chain hashing)

Each test below specifies: Purpose, Preconditions, Steps, Expected Results, Failure Guidance.

## 2. Environment Assumptions
- FastAPI app import path: `src.api.server:app`
- Python 3.11+ virtual environment active
- Optional deps (transformers, torch, prometheus_client) may be absent; tests must degrade gracefully
- Database may be unavailable; tests that rely on DB either mock or soft-assert (skip if unreachable)

## 3. Test Execution Profiles
| Profile | Command | Scope |
|---------|---------|-------|
| Smoke | `pytest -k "(e2e_endpoint_hunter or artifact_scanner_escalation or file_batch_custody)" -q` | Core behavior in <60s |
| Full Functional | `pytest -q` | All existing repository tests |
| Focus: Endpoint | `pytest -k endpoint_hunter -q` | Endpoint hunter module + e2e overlay |
| Focus: Artifacts | `pytest -k artifact_scanner_escalation -q` | Artifact pipeline risk & escalation |

## 4. New / Augmented Test Cases

### 4.1 Endpoint Hunter E2E (New)
**File:** `tests/test_e2e_endpoint_hunter.py`
- Rare lineage factor appears first occurrence and disappears after N (> rare_cutoff) sightings.
- Benign common parent-child pair yields zero `endpoint:` factors.
- (Extension candidate) Add persistence + burst combo scenario.

### 4.2 Artifact Scanner Ambiguity & High Risk (New)
**File:** `tests/test_artifact_scanner_escalation.py`
- Mixed batch producing an ambiguity-band artifact (`plink.exe` with tunneling + fresh download) and a high-risk packed unsigned binary.
- Ensures factor presence and relative risk ordering.

### 4.3 File Batch Custody + Index (Existing Enhanced)
**File:** `tests/test_file_batch_custody.py`
- Validates custody digest recomputation equals stored hash (deterministic ordering / JSON canonicalization).
- Asserts in-memory `FILE_HASH_FACTORS` updated for factorized file.

### 4.4 SBOM Vulnerability Mapping (Existing)
**File:** `tests/test_sbom_vuln_mapper.py`
- Ensures scaling & capping semantics; vulnerability factor contributions do not exceed global cap.
- (Addendum recommendation) Add scenario with mixed severities to verify proportional weighting.

### 4.5 Endpoint Hunter Unit Micro (Existing)
**File:** `tests/test_endpoint_hunter.py`
- Stabilization of rare lineage and exec burst detection in isolation.

### 4.6 Escalation Decision Scenario (Planned)
**Status:** TODO (test id: ESC-DEC-01)
**Goal:** Force a decision into deep path (confidence mid-band) then escalate (simulate stronger factors) verifying final verdict transitions and factor set expanded.
**Approach Draft:**
1. Temporarily monkeypatch decision thresholds -> benign=0.05 malicious=0.95.
2. Craft pipeline result with confidence 0.40 (should route to deep analysis).
3. Deep analysis mock adds additional factors pushing confidence to 0.92 (still below malicious threshold) — escalate path flag expected.
4. Assert final decision factors include synthetic escalation indicator (module instrumentation needed or fixture stub).

### 4.7 Auto-Attach Retro Correlation (Planned)
**Status:** TODO (test id: FILE-AUTO-01)
**Goal:** Submit a file batch; then ingest an event referencing that file hash; assert `decision.update.file_factors` emitted and decision factors enriched.
**Prereq:** Outbound consumer buffer + dedupe set (future patch).

### 4.8 Duplicate Suppression (Planned)
**Status:** TODO (test id: FILE-DEDUP-01)
**Goal:** Emit two identical auto-attach updates (same event_id+file_hash); buffer should store only one; retro mode update must still store.

## 5. Coverage Matrix (High-Level)
| Domain | Factors / Behaviors | Covered By | Gap |
|--------|---------------------|------------|-----|
| Endpoint lineage rarity | `endpoint:rare_lineage` stabilization | endpoint_hunter unit + e2e | None |
| Exec burst | `endpoint:exec_burst` | endpoint_hunter unit | Add e2e assert in future |
| Persistence | `endpoint:persistence_candidate` | (not yet in e2e) | Add synthetic event |
| Signed mismatch | `endpoint:signed_mismatch` | (unit potential) | Add dedicated test |
| Artifact LOLBin | `lolbin_misuse` | artifact escalation test | None |
| Tunneling | `tunneling_utility` | artifact escalation test | None |
| Fresh download | `fresh_download` | artifact escalation test | None |
| Packed section | `high_entropy_section` | artifact escalation test | None |
| Unsigned binary | `unsigned_binary` | artifact escalation test | None |
| Macro autoexec/obfuscation | (present in new batch extension) | Add assert for macro doc | Minor |
| SBOM vuln factors | `sbom:*` capped | sbom_vuln_mapper test | Add multi-severity mix |
| File triage factors | `file:*` | file_batch_custody test | Add auto-attach SSE test |
| Custody hashing | deterministic digest | file_batch_custody | None |
| Decision explanation | Weight & provenance grouping | explain endpoint test | None |
| Escalation model chain | risk_confidence refinement | artifact escalation test (trace) | Add explicit assertion for trace path |

## 6. Failure Diagnostics Guidance
| Symptom | Likely Cause | Next Step |
|---------|-------------|----------|
| Rare lineage never clears | `rare_cutoff` mis-set or test not generating enough repeats | Inspect `EndpointHunter.rare_cutoff` via introspection |
| Ambiguous artifact risk <0.30 | Factor weight changes | Print `factors` and recompute weights manually using `FACTOR_WEIGHTS` |
| High-risk artifact not > ambiguous | Weight drift or missing entropy flags | Confirm test payload includes `entropy_high_section` & unsigned |
| Custody hash mismatch | Non-deterministic serialization | Ensure `sort_keys=True` and consistent separators | 
| SBOM test flakiness | Non-isolated repo state | Clear or temp directory fixture isolation |

## 7. Execution Order Recommendation
1. Smoke: Endpoint + Artifact + File Custody
2. SBOM Mapping
3. Explanation / Governance tests (optional) 
4. Planned (once implemented): Auto-Attach + Duplicate Suppression + Escalation Deep Path

## 8. Sample Manual Verification Snippets
```powershell
# Rare lineage replay manual check
Invoke-RestMethod http://localhost:8080/debug/decision/e2e-rare-1 | ConvertTo-Json -Depth 6

# Artifact report factors
Invoke-RestMethod http://localhost:8080/api/v1/artifacts/latest_report | ConvertTo-Json -Depth 4

# Custody log tail
Get-Content data/file_batches/custody.jsonl -Tail 5
```

## 9. Non-Lazy Verification Checklist
- [x] New E2E coverage for endpoint hunter beyond internal module unit.
- [x] Artifact ambiguity vs high-risk scenario with distinct factor sets.
- [x] Deterministic custody verification present.
- [x] Generator script for reproducibility.
- [ ] Escalation deep decision path (await implementation).
- [ ] Auto-attach + dedupe tests pending infrastructure patch.
- [ ] Additional macro document explicit assert (optional minor).

## 10. Roadmap for Remaining Test Gaps
| Priority | Test ID | Rationale | Effort |
|----------|---------|-----------|--------|
| High | ESC-DEC-01 | Validates deep analysis escalation contract | Medium |
| High | FILE-AUTO-01 | Ensures retro file factor propagation transparency | Medium |
| High | FILE-DEDUP-01 | Prevents event storm amplification | Low |
| Medium | END-PERSIST-01 | Persistence heuristic accuracy | Low |
| Medium | END-SIGNED-01 | Signed mismatch confidence delta correctness | Low |
| Medium | SBOM-MIX-01 | Severity weighting regression protection | Low |
| Low | ART-MACRO-ASSERT | Ensure macro factors presence after weight tuning | Low |

## 11. How to Extend (Template)
```python
def test_new_behavior_example():
    # Arrange
    payload = {...}
    r = client.post('/api/v1/events', json=payload)
    assert r.status_code == 200
    rec = _wait_decision(payload['id'])
    # Assert factor invariants
    assert 'new:factor' in rec.factors
    # Assert confidence constraints
    assert 0.2 <= rec.confidence <= 0.6
```

## 12. Integrity & Evidence
- All added tests are executable now (see repository path references). 
- This document centralizes scenario intent so an external agent (e.g. Claude) can parse and generate additional concrete test modules mechanically.

---
**End of Test Plan**
