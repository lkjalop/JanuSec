**Errors And Threats By Domain**

Overview
- **Purpose**: quick reference table listing common errors/threats by domain (Network, Endpoint, Email, Cloud, API/Application, Data) and how the Janusec platform detects and surfaces them.
- **Audience**: SOC analysts, incident responders, platform integrators.

Table: errors/threats per domain

| Domain | Common Errors / Threats | Detection Signals | How Janusec Surfaces It |
|---|---|---|---|
| Network | - Port scans, SYN floods, DDoS, suspicious DNS (NXDOMAIN spikes), BGP hijack indicators | - Traffic volume spikes, connection flags, repeated failed connections, NXDOMAIN ratio, ASN rarity | - Dashboard alerts, HopGraph correlation highlighting overlapping IP/path clusters, EWMA-smoothed metrics, triage score > threshold triggers incident |
| Endpoint | - Malicious binaries, process injection, uncommon loadable modules, persistence mechanisms | - File hashes, anomalous process names, unusual parent/child relationships, eBPF/ETW signatures | - Row-level findings in CSV Analyzer, LLMAssessment tier2 summaries, evidence links, recommended playbooks |
| Email | - Phishing, malicious attachments, credential harvesting | - Indicators in attachment hashes, suspicious URLs, sender reputation, DKIM/SPF failures | - Integrations (webhook) to SIEM, incidents with verdicts, exportable investigation reports |
| Cloud | - Misconfigured buckets, excessive API calls, compromised keys, suspicious IAM activity | - Unusual API sequences, geolocation anomalies, high error rates (403/401), role assumption patterns | - Timeline views, hopgraph linking cloud events to endpoints, scoring with domain-context weightings |
| API / Application | - Broken auth, SQLi attempts, high error rates, anomalous user agents | - Error rate, signature match, high-cardinality parameter values, abnormal paths | - Metrics dashboard, correlation to upstream alerts, actor-level grouping in HopGraph |
| Data / Database | - Exfiltration, data corruption, unauthorized queries | - High-volume SELECTs, slow queries, abnormal table access patterns, unexpected exports | - Data access alerts, triage prioritization, suggested containment actions |

How Janusec Computes Risk (brief)
- Inputs: row-level factors, DREAD-style signals, factor density, confidence, rarity metrics (ASN rarity, file rarity)
- Scoring: composite triage score used to prioritize backfill and incident generation. Scores fed into UI and ETA engine for backfill.

User Actions and Outputs
- **Investigate**: click a row -> `Tier 2` deep LLM summary with persona-based output. Links to supporting evidence and exported playbooks.
- **Backfill**: run adaptive backfill -> progress persisted per assessment. ETA displayed in UI.
- **Export**: export investigation report in HTML including model explanations and scenario mappings.

References and Files
- See `frontend/static/janusec-platform-complete-LIVE.html` for UI anchors and `src/api/csv_endpoints.py` for backfill orchestration.
