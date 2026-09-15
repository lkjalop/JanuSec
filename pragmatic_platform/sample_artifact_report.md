# Artifact Intelligence Executive & Technical Report
Date: 2025-09-23 14:32 UTC
Source Files: `dump/cybstash csv1.xlsx`, `dump/Cyberstash_csv2.xlsx`
Batches Simulated: BATCH-CYBSTASH-CSV1, BATCH-CYBSTASH-CSV2

---
## 1. Executive Posture Summary
Overall Posture: **Elevated** – 2 high / malicious artifacts require action.
New Techniques Since Prior Batch: `T1566 (Phishing Attachment)`, `T1204 (User Execution)`
Propagation: `powerscan.exe` present on 4 distinct hosts (multi-host spread factor triggered).
Business Impact (Condensed): Potential early-stage discovery tooling coupled with macro-based delivery may enable credential harvesting or lateral movement if uncontained.
Confidence: **High** (low ambiguity; consistent factor patterns; strong negative reputation match).

### Top 3 Artifacts (Risk Focus)
1. **powerscan.exe** – MALICIOUS 87 – Unsigned discovery tool; multi-host; negative VT rep (8/62).  
2. **macro_payload.dotm** – HIGH 72 – AutoExec macro; obfuscation; external download; off-hours execution.  
3. **backup_agent.exe** – BENIGN 12 – Trusted signature; common baseline (noise floor reference).  

### Recommended Immediate Actions
- Contain affected hosts: HR-LAPTOP-22, FIN-SVR-01, FIN-LAPTOP-03, HR-LAPTOP-07.
- Quarantine macro payload & block external macro-enabled documents at mail gateway.
- Review Cluster #12 for additional discovery/credential staging binaries.

---
## 2. Technique & Coverage Overview
| Category | Items | Delta |
|----------|-------|-------|
| MITRE Techniques | T1059, T1105, T1566, T1204 | + T1566, T1204 this batch |
| STRIDE | Tampering, Elevation of Privilege, Repudiation, Information Disclosure | + Repudiation, Info Disclosure |

Delta Explanation: Macro initial access introduced phishing/user-execution vectors not previously observed in baseline batch.

---
## 3. Artifact Table (Condensed)
| Name | Type | Risk | Verdict | Rarity | Hosts | Cluster | Key Factors |
|------|------|------|---------|--------|-------|---------|-------------|
| powerscan.exe | EXECUTABLE | 87 | MALICIOUS | RARE | 4 | 12 | Unsigned; Multi-host; Rare; VT Negative |
| macro_payload.dotm | MACRO | 72 | HIGH | EMERGING | 1 | 7 | AutoExec; Obfuscation; External DL |
| backup_agent.exe | EXECUTABLE | 12 | BENIGN | COMMON | 15 | — | Signed; Common |

---
## 4. Factor Contributions (Top Artifacts)
### powerscan.exe
| Category | Δ | Notes |
|----------|---|-------|
| STATIC | +18 | Unsigned binary (missing publisher) |
| RELATIONAL | +15 | Spread: 4 hosts |
| RARITY | +10 | First appearance |
| TEMPORAL | +8 | Burst within 10m window |
| REPUTATION | +20 | VT 8/62 detections |
| SCRIPT | +6 | Spawns PowerShell child |
| ORIGIN | +10 | Download path user profile |

### macro_payload.dotm
| Category | Δ | Notes |
|----------|---|-------|
| MACRO | +20 | AutoOpen routine |
| ORIGIN | +10 | Recent external download (<2h) |
| STATIC | +8 | Obfuscated Base64 strings |
| TEMPORAL | +6 | Off-hours execution (03:14) |
| RELATIONAL | +5 | Spawns wscript.exe |
| RARITY | +5 | Emerging (batch-limited) |
| REPUTATION | +18 | Malicious macro signature |

---
## 5. Propagation & Prevalence
- Multi-Host Artifact(s): 1 (powerscan.exe)
- Rare or Emerging Artifacts: 2 (powerscan.exe rare; macro_payload.dotm emerging)
- Common Baseline Reference: backup_agent.exe (seen across 5 batches; stable prevalence)

---
## 6. Business Impact Narrative
The presence of an unsigned discovery-oriented binary (`powerscan.exe`) on multiple heterogeneous hosts indicates early internal reconnaissance. Concurrent emergence of a malicious Office macro suggests an initial access foothold used for tool staging. Without containment, escalation paths could include credential dumping and lateral traversal. Rapid action reduces the probability of privilege escalation.

---
## 7. Recommended Tactical & Strategic Actions
| Priority | Action | Rationale |
|----------|--------|-----------|
| High | Network isolate affected hosts | Halt lateral spread of discovery tooling |
| High | Block macro-enabled inbound mail attachments | Remove initial access delivery vector |
| Medium | Expand hunt for cluster #12 variants | Identify further reconnaissance binaries |
| Medium | Add YARA rule for macro obfuscation pattern | Improve early detection |
| Low | Baseline signed admin tools inventory | Reduce noise & false positives |

---
## 8. Coverage Delta Detail
Previous Batch Coverage: T1059, T1105  
Current Batch Coverage: T1059, T1105, T1566, T1204  
Delta Driver: Macro attachment introduced **Phishing (T1566)** and **User Execution (T1204)** heuristics.

---
## 9. Confidence & Ambiguity
Ambiguity Gating: Not triggered (risk well above threshold; consistent static + relational + reputation convergence).
LLM Refinement: Not invoked (low ambiguity band). No artificial risk inflation applied.

---
## 10. Appendices
### 10.1 Raw JSON Extract
See `sample_artifact_report.json`.

### 10.2 Glossary
- Rare: First time seen artifact
- Emerging: Low recurrence; limited spread
- Cluster: Group of semantically similar artifacts (embedding + heuristic)

---
End of Report
