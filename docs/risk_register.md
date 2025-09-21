# Threat Sifter Platform - Risk Register (Initial Draft)

| ID | Risk Description | Category | Impact | Likelihood | Inherent Risk | Key Mitigations | Residual Risk | Owner | Notes |
|----|------------------|----------|--------|------------|---------------|-----------------|---------------|-------|-------|
| R1 | Database outage causes loss of decision persistence | Availability | High | Medium | High | Async queue buffering, retry logic (planned), graceful degrade to in-memory | Medium | Platform Eng | Add retry + circuit breaker on DB writes |
| R2 | Model drift increases false negatives over time | ML Quality | High | Medium | High | Drift monitoring (planned), periodic retraining, human review loop | Medium | Data Science | Add statistical drift metrics & auto alerts |
| R3 | High false positive rate overwhelms analysts | Operations | High | Medium | High | Confidence thresholds, adaptive tuner feedback, playbook auto-closures | Medium | SecOps Lead | Add weekly FP rate dashboard |
| R4 | Slack webhook compromise leaks alert data | Security | Medium | Low | Medium | Store secret in vault (planned), limited scopes, rotate keys | Low | Security Eng | Add secret rotation SOP |
| R5 | PII leakage in logs or alerts | Privacy | High | Low | High | PII redaction module, audit reviews, masking tests | Low | Privacy Officer | Add redaction counter metric (done) |
| R6 | Queue saturation leading to dropped events | Performance | High | Medium | High | Backpressure policies (implemented), metrics & alerting | Medium | Platform Eng | Add autoscale policy guidance |
| R7 | External AI latency slows pipeline | Performance | Medium | Medium | Medium | Tiered fallback (implemented), 1s timeout wrapper | Low | AI Lead | Add latency histogram for external calls |
| R8 | Supply chain vulnerability in OSS models | Security | High | Low | High | Pin versions, hash verification (planned), SBOM generation | Medium | Security Eng | Add dependency scanning pipeline |
| R9 | Schema drift between services breaks parsing | Data | Medium | Medium | Medium | Pydantic validation (added), contract tests (planned) | Low | Platform Eng | Add CI contract test suite |
| R10 | Custody hash tampering undetected | Integrity | High | Low | High | Hash chain (implemented), audit log immutable retention | Low | Compliance | Encrypt backups |
| R11 | Alert storm during incident floods channels | Operations | Medium | Medium | Medium | Slack rate limiting (implemented), severity routing | Low | SecOps Lead | Add dynamic suppression rules |
| R12 | Credentials leaked via debug logging | Security | High | Low | High | Structured logging, secret scrubber (planned), code review | Low | Security Eng | Add log scanning tool |
| R13 | Regulatory non-compliance (retention) | Compliance | High | Low | High | Data retention config (planned), purge jobs | Medium | Compliance | Define retention policy |
| R14 | Insider misuse of adaptive tuner | Governance | Medium | Low | Medium | Approval queue for risky changes, audit trail | Low | Governance | Add role-based gating |

## Next Actions
- Add drift monitoring instrumentation (R2)
- Implement DB write retry with jitter (R1)
- Build FP rate dashboard & weekly report (R3)
- Vault integration for secrets (R4)
- Add SBOM + dependency scan step (R8)
- Implement retention & purge scheduler (R13)

_Last updated: automatic generation seed_
