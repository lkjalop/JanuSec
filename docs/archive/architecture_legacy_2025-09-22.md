# Legacy Architecture Snapshot (Archived) \n\nDate Archived: 2025-09-22  \nPlatform Version Context: v0.9.0-pre (Pre-Production Validation Update)  \n\nThis file preserves the original high-level architecture ASCII diagrams prior to the introduction of explicit cost ledger instrumentation, FP taxonomy integration, rubric scoring formalization, correlation TP/FP before/after counters, and multi-tenant isolation stress harness documentation.\n\nRationale for Archival:  \n- Maintain historical traceability for audit & evolution justification  \n- Support executive narrative of maturity progression  \n- Provide baseline for future delta diffs & design rationale annotations  \n\n## Original High-Level Architecture (Pre-Governance Expansion)\n\n```
       +----------------------+           +----------------------+ 
  Telemetry --->  |  Ingestion API /    |  enqueue  |   In-Memory Event    | 
 (XDR, agents,    |  Normalization      |  ----->   |      Queue           | 
  logs, enrich)   +----------+-----------           +-----------+----------+ 
         |                                   | 
         v                                   v (worker consumes) 
       +-------------+                    +---------------------+ 
       | Orchestrator|------------------->| Progressive Pipeline | 
       |  (registry  |                    |  1. Baseline        | 
       |  & lifecycle)|                   |  2. Regex           | 
       +------+------+                    |  3. Adaptive Blend  | 
         |                           |  4. (Optional Deep) | 
       +-----------+----------+                +----------+----------+ 
       | Custody Chain /      |                           | 
       | Audit Hashing        |<--------------------------+ 
       +-----------+----------+                           | 
         |                                      | 
         v                                      v 
          +------------------+                   +-------------------+ 
          | Decision Storage |<------------------| Feedback / Weights| 
          +---------+--------+                   +-------------------+ 
          |                                       | 
          v                                       v 
         +--------------------+             +--------------------------+ 
         | Observability      |<------------| Drift Analyzer (JS Div.) | 
         | (Prometheus + SSE) |             +--------------------------+ 
         +----------+---------+ 
          | 
          v 
       +---------------+ 
       | Analyst & API | 
       | (NLP, Similar)| 
       +---------------+ 
```\n\n```
┌─────────────────────────────────────────────────────────┐ 
│                 Data Ingestion                          │ 
│           (Eclipse XDR + Network Taps)                 │ 
└─────────────────┬───────────────────────────────────────┘ 
                  │ 
                  ▼ 
┌─────────────────────────────────────────────────────────┐ 
│              Main Orchestrator                          │ 
│         (Circuit Breakers + Health Checks)             │ 
└─────────┬─────────────────────────┬─────────────────────┘ 
          │                         │ 
          ▼                         ▼ 
┌─────────────────┐       ┌─────────────────────────────────┐ 
│ Fast Path       │       │      Deep Analysis Pipeline    │ 
│ • Baseline      │       │  • Network Hunter              │ 
│ • Regex Engine  │       │  • Endpoint Hunter             │ 
│ • Confidence    │       │  • Compliance Mapper           │ 
└─────────────────┘       │  • Adaptive ML Models          │ 
                          └─────────────────────────────────┘ 
                                        │ 
                                        ▼ 
                          ┌─────────────────────────────────┐ 
                          │        SOAR Integration         │ 
                          │     (Playbook Execution)       │ 
                          └─────────────────────────────────┘ 
```\n\n## Notes\n- This snapshot predates explicit enumeration of governance & measurement subsystems in the primary diagram set.  \n- Subsequent architecture evolution isolates *governance, observability, cost, correlation measurement, and reproducibility* as first-class domains.  \n\nRefer to `../architecture_evolution.md` for the current architecture with maturity-layer annotations.\n