# Risk Register

| ID | Risk | Category | Likelihood | Impact | Mitigation | Owner | Status |
|----|------|----------|------------|--------|------------|-------|--------|
| R1 | Early confidence misroutes true malicious | Detection | Med | High | Shadow evaluation + replay gating | TBD | Open |
| R2 | TI cache outage increases FN rate | Availability | Med | Med | Multi-source + TTL fallback | TBD | Open |
| R3 | Redis hot tier failure | Infra | Med | Med | In-process LRU fallback, degrade factor weight | TBD | Open |
| R4 | LOC cap causes duplicate logic | Engineering | Med | Med | Shared utility pkg + lint rule | TBD | Open |
| R5 | Factor explosion reduces precision | Detection | Med | Med | Factor pruning via coverage & ablation | TBD | Open |
| R6 | Playbook action runaway | Response | Low | High | Action cap + circuit breaker | TBD | Open |
| R7 | Chain of custody mismatch undetected | Integrity | Low | High | Scheduled verification job + alert | TBD | Open |
| R8 | NLP intent misinterpretation leads to wrong query | UX | Med | Low | Confidence threshold + clarification prompt | TBD | Open |
| R9 | Configuration drift untracked | Governance | Low | High | Config digests + change factor | TBD | Open |
| R10 | APT low-and-slow evasion | Detection | Med | High | Temporal expansion + multi-stage state machine | TBD | Open |

## Process
- Review weekly; update status & owners.
- Promote closed risks to lessons-learned doc.

## Risk Scoring (Optional Future)
Simple matrix (1–3) * (1–3) → priority ordering.
