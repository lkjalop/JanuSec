# Janusec MVP Execution Matrix 2026 Q1

## Working Goal

Build a sellable MVP around:

- AWS + Azure first
- network + endpoint first
- deterministic T1 first
- reliable async T2 second
- false-positive reduction first
- on-demand evidence collection as a gated escalation aid
- self-hosted / private-cloud first

This matrix is the execution view of [MVP_IMPLEMENTATION_BREAKDOWN_2026_Q1.md](C:/AI/janusec/MVP_IMPLEMENTATION_BREAKDOWN_2026_Q1.md).

## Cloud Sources to Ingest First

### AWS: Top 4 to Ingest First

1. `CloudTrail`
- Why: identity, API misuse, privilege escalation, console access, key abuse
- Correlates well with: GuardDuty, IAM anomalies, endpoint identity pivots

2. `GuardDuty`
- Why: curated findings, exposed credentials, anomalous API usage, workload threats
- Correlates well with: CloudTrail, VPC Flow, known IOC enrichment

3. `VPC Flow Logs` or normalized Zeek-style network feeds
- Why: east-west and north-south connection evidence, beaconing, egress anomalies
- Correlates well with: GuardDuty, endpoint process lineage, DNS/IOC signals

4. `SecurityHub` optional but recommended
- Why: control/finding aggregation layer that helps summarize AWS risk posture
- Correlates well with: GuardDuty and configuration drift narratives

### Azure: Top 4 to Ingest First

1. `Entra ID Sign-In Logs`
- Why: impossible travel, auth burst, suspicious sign-ins, token misuse
- Correlates well with: endpoint auth events, CloudTrail identity issues, threat actor identity pivots

2. `Entra ID Audit Logs`
- Why: app consent changes, role changes, policy changes, user lifecycle abuse
- Correlates well with: sign-in logs, account takeover sequences, administrative drift

3. `Azure Event Hub` as the transport/control-plane ingestion path
- Why: practical ingestion entry for many Azure-native log pipelines
- Correlates well with: Entra, Defender, Microsoft telemetry exports

4. `Defender for Cloud` or `Microsoft Defender XDR export path`
- Why: cloud posture findings, workload alerts, cloud-resource compromise hints
- Correlates well with: Entra, endpoint alerts, network anomalies

## Correlation Priorities for HopGraph

The first correlation value comes from linking these entity families:

- `principal`
  - AWS IAM user, role, access key
  - Azure Entra user, service principal, app
- `host`
  - endpoint device name
  - instance / workload / VM
- `network`
  - source IP
  - destination IP
  - domain
  - port
- `artifact`
  - process hash
  - URL
  - email / indicator / filename
- `time`
  - same 5-15 minute window
  - same session chain

The first high-value correlation stories to ship are:

1. `IAM misuse + network egress`
- CloudTrail or Entra auth event
- plus GuardDuty / Defender finding
- plus VPC Flow or Zeek egress anomaly

2. `Identity anomaly + endpoint execution`
- Entra sign-in or auth burst
- plus Sysmon process lineage
- plus suspicious destination or IOC

3. `Administrative change + suspicious workload activity`
- Entra audit or CloudTrail privilege/config change
- plus endpoint or network anomaly

4. `Known IOC reuse across cloud and endpoint`
- same IP/domain/hash/user across multiple alert families

## CSV / XLSX Single and Multi Upload

This is already present and should stay in scope.

Real files today:
- [`src/api/csv_endpoints.py`](C:/AI/janusec/src/api/csv_endpoints.py)
- [`src/api/csv_multi_endpoints.py`](C:/AI/janusec/src/api/csv_multi_endpoints.py)
- [`src/api/csv_handler.py`](C:/AI/janusec/src/api/csv_handler.py)
- [`src/api/csv_mapping_endpoints.py`](C:/AI/janusec/src/api/csv_mapping_endpoints.py)
- [`src/api/upload_endpoints.py`](C:/AI/janusec/src/api/upload_endpoints.py)

How it should be positioned:
- as a bulk telemetry onboarding path
- as a demo/pilot ingestion path
- as a backfill path
- not as a separate “CSV-only product”

What to do:
- keep single upload and multi upload
- normalize everything into the same canonical event envelope as AWS/Azure/endpoint ingest
- run the same T1/T2 policy on uploaded rows
- avoid custom CSV-only classification logic drifting away from the main pipeline

Recommended behavior:
- upload CSV/XLSX
- parse and normalize
- dedupe and cluster
- T1 over all rows
- T2 only over selected top-risk alerts
- output analyst/manager/forensics summaries

## Execution Matrix

| File | Owner | Priority | Effort | Dependency | Done Definition | Launch Blocker |
|---|---|---:|---:|---|---|---|
| [`src/core/event_pipeline/pipeline.py`](C:/AI/janusec/src/core/event_pipeline/pipeline.py) | Backend / detection engineer | Critical | M | canonical envelope, tier1 summarizer, redis tier2 | Every alert gets T1; fallback correlation emitted; selective T2 enqueue works | Yes |
| [`src/core/correlation/tier1_summarizer.py`](C:/AI/janusec/src/core/correlation/tier1_summarizer.py) | Detection engineer | Critical | M | factor extraction, pipeline | Deterministic summary is stable, short, evidence-first, no LLM dependency | Yes |
| [`src/queue/redis_tier2.py`](C:/AI/janusec/src/queue/redis_tier2.py) | Backend / platform | Critical | M | Redis, pipeline ids | T2 jobs enqueue in 5-10 sized units with tenant-safe concurrency and writeback | Yes |
| [`src/api/routes/events.py`](C:/AI/janusec/src/api/routes/events.py) | API engineer | Critical | M | stream ingest, endpoint normalizers | Network + endpoint ingest routes land into canonical pipeline reliably | Yes |
| [`src/api/stream_ingest.py`](C:/AI/janusec/src/api/stream_ingest.py) | API engineer | Critical | M | envelope normalization | Chunking, backpressure, and canonical event formatting are enforced | Yes |
| [`src/connectors/sysmon_evtx.py`](C:/AI/janusec/src/connectors/sysmon_evtx.py) | Endpoint engineer | Critical | M | endpoint route, canonical schema | Sysmon/EVTX-derived process lineage is ingested with stable field mapping | Yes |
| [`src/connectors/aws/cloudtrail.py`](C:/AI/janusec/src/connectors/aws/cloudtrail.py) | Cloud connector engineer | Critical | S | AWS creds, polling route | CloudTrail poller supports bounded pull, checkpoint, and health state | Yes |
| [`src/connectors/aws/guardduty.py`](C:/AI/janusec/src/connectors/aws/guardduty.py) | Cloud connector engineer | Critical | S | AWS creds, polling route | GuardDuty findings normalize into canonical schema with entity keys | Yes |
| [`src/connectors/aws/vpcflow.py`](C:/AI/janusec/src/connectors/aws/vpcflow.py) | Cloud connector engineer | Critical | M | network schema | VPC Flow records map into network primitives and correlate with identity/IOC | Yes |
| [`src/api/connectors_cloudtrail.py`](C:/AI/janusec/src/api/connectors_cloudtrail.py) | API engineer | Critical | S | AWS connector | HTTP-triggered poll/health/checkpoint route exists for CloudTrail | Yes |
| [`src/api/connectors_sysmon.py`](C:/AI/janusec/src/api/connectors_sysmon.py) | API engineer | Critical | S | sysmon connector | Sysmon connector can be triggered, checked, and validated via API | Yes |
| [`src/connectors/azure/__init__.py`](C:/AI/janusec/src/connectors/azure/__init__.py) | Cloud connector engineer | Critical | S | package creation | Azure connector package exists and is importable | Yes |
| [`src/connectors/azure/base.py`](C:/AI/janusec/src/connectors/azure/base.py) | Cloud connector engineer | Critical | S | azure package | Shared auth/config/checkpoint model exists for Azure connectors | Yes |
| [`src/connectors/azure/event_hub.py`](C:/AI/janusec/src/connectors/azure/event_hub.py) | Cloud connector engineer | Critical | M | Azure auth, event hub config | Event Hub consumer can receive and normalize inbound records | Yes |
| [`src/connectors/azure/entra_id.py`](C:/AI/janusec/src/connectors/azure/entra_id.py) | Cloud connector engineer | Critical | M | Azure auth, Graph or exported logs | Sign-in and audit logs normalize into canonical identity event schema | Yes |
| [`src/connectors/azure/defender_cloud.py`](C:/AI/janusec/src/connectors/azure/defender_cloud.py) | Cloud connector engineer | Critical | M | Azure auth | Defender findings normalize into cloud-security finding schema | Yes |
| [`src/connectors/azure/normalizer.py`](C:/AI/janusec/src/connectors/azure/normalizer.py) | Detection engineer | Critical | S | azure sources | Entity keys are extracted consistently for HopGraph | Yes |
| [`src/api/routes/azure.py`](C:/AI/janusec/src/api/routes/azure.py) | API engineer | Critical | S | azure connectors | Azure poll/health/checkpoint routes are mounted and usable | Yes |
| [`src/api/server.py`](C:/AI/janusec/src/api/server.py) | Platform engineer | Critical | S | new routes | New AWS/Azure/feedback/evidence routes are included and healthy | Yes |
| [`src/api/app.py`](C:/AI/janusec/src/api/app.py) | Platform engineer | Critical | S | route registration | App boots with self-hosted MVP routes and health checks intact | Yes |
| [`src/analysis/persona_format.py`](C:/AI/janusec/src/analysis/persona_format.py) | Detection engineer / PM | High | M | T1/T2 outputs | Analyst, manager, and forensics formats are distinct and useful | Yes |
| [`src/api/report_endpoints.py`](C:/AI/janusec/src/api/report_endpoints.py) | API engineer | High | M | persona formatting | Reports render from T1-only or T1+T2 data without missing sections | Yes |
| [`src/api/executive_report_endpoints.py`](C:/AI/janusec/src/api/executive_report_endpoints.py) | API engineer | High | M | persona formatting | Manager report is short, non-technical, and evidence-backed | No |
| [`src/api/routes/feedback.py`](C:/AI/janusec/src/api/routes/feedback.py) | Detection engineer | High | M | factor quality, adaptive tuner | Feedback changes suppression/baseline candidates and later scoring inputs | Yes |
| [`src/api/decision_feedback_endpoints.py`](C:/AI/janusec/src/api/decision_feedback_endpoints.py) | API engineer | High | M | feedback route | Decision-level feedback persists and can be replayed into tuning flow | Yes |
| [`src/core/quality/factor_quality.py`](C:/AI/janusec/src/core/quality/factor_quality.py) | Detection engineer | High | M | feedback labels | Factors get quality tracking tied to legit/suspicious/malicious outcomes | Yes |
| [`src/modules/adaptive_tuner.py`](C:/AI/janusec/src/modules/adaptive_tuner.py) | Detection engineer | High | M | factor quality | Adaptive tuning updates are visible, bounded, auditable, and testable | No |
| [`src/api/routes/evidence.py`](C:/AI/janusec/src/api/routes/evidence.py) | API engineer | High | M | request registry | Analyst can request memory/KAPE/PCAP follow-up without autonomous execution | Yes |
| [`src/core/evidence/request_registry.py`](C:/AI/janusec/src/core/evidence/request_registry.py) | Backend engineer | High | M | evidence route | Evidence requests are persisted, gated, and linked to alert/report ids | Yes |
| [`src/api/forensics_endpoints.py`](C:/AI/janusec/src/api/forensics_endpoints.py) | API engineer | High | M | evidence registry | Forensics view shows requested next-step collection, not just static text | No |
| [`src/api/csv_endpoints.py`](C:/AI/janusec/src/api/csv_endpoints.py) | API engineer | High | M | csv handler, pipeline | CSV/XLSX upload feeds the same canonical alert path and batch policy | Yes |
| [`src/api/csv_multi_endpoints.py`](C:/AI/janusec/src/api/csv_multi_endpoints.py) | API engineer | High | M | csv handler, pipeline | Multi-upload behaves like bulk ingest and preserves source/session metadata | No |
| [`src/api/csv_handler.py`](C:/AI/janusec/src/api/csv_handler.py) | Backend engineer | High | L | normalization rules | CSV/XLSX parsing normalizes rows into canonical source families with chunking | Yes |
| [`src/api/csv_mapping_endpoints.py`](C:/AI/janusec/src/api/csv_mapping_endpoints.py) | API engineer | Medium | M | csv handler | Mapping presets work for customer-provided exports and reduce onboarding friction | No |
| [`docker-compose.yml`](C:/AI/janusec/docker-compose.yml) | Platform engineer | High | S | service list | MVP profile is sane; partial services disabled or flagged | Yes |
| [`docker-compose.selfhosted.yml`](C:/AI/janusec/docker-compose.selfhosted.yml) | Platform engineer | High | M | compose baseline | Customer can boot api + worker + ollama + postgres + redis with one file | Yes |
| [`.env.example`](C:/AI/janusec/.env.example) | Platform engineer | High | S | compose | Required env vars are documented with safe defaults | Yes |
| [`docs/SELF_HOSTED_QUICKSTART.md`](C:/AI/janusec/docs/SELF_HOSTED_QUICKSTART.md) | PM / platform | High | S | compose | Customer admin can deploy on VM/private cloud without tribal knowledge | Yes |
| [`docs/DEPLOYMENT_NUTANIX.md`](C:/AI/janusec/docs/DEPLOYMENT_NUTANIX.md) | Platform engineer | Medium | S | quickstart | Nutanix/private-cloud deployment pattern is documented for sales/pilots | No |
| [`grafana/dashboards/mvp_ingest.json`](C:/AI/janusec/grafana/dashboards/mvp_ingest.json) | Platform engineer | Medium | M | metrics | Ingest throughput, error, and backlog are visible | No |
| [`grafana/dashboards/mvp_pipeline.json`](C:/AI/janusec/grafana/dashboards/mvp_pipeline.json) | Platform engineer | Medium | M | metrics | T1 latency, T2 queue lag, and report generation are visible | No |
| [`grafana/dashboards/mvp_feedback.json`](C:/AI/janusec/grafana/dashboards/mvp_feedback.json) | Detection engineer | Medium | M | feedback metrics | False-positive trends and feedback loop effects are visible | No |
| [`docs/MVP_DEMO_SCRIPT.md`](C:/AI/janusec/docs/MVP_DEMO_SCRIPT.md) | PM / founder | Medium | S | MVP scope | CEO and sales demo can be run consistently in under 10 minutes | No |
| [`docs/MVP_LIMITATIONS.md`](C:/AI/janusec/docs/MVP_LIMITATIONS.md) | PM / founder | Medium | S | MVP scope | Partial/stub features are clearly documented and hidden from overclaiming | No |
| [`docs/MVP_SALES_POSITIONING.md`](C:/AI/janusec/docs/MVP_SALES_POSITIONING.md) | PM / founder | Low | S | MVP scope | Sales and investor wording matches actual product state | No |

## Suggested Owners

If you do not have named people yet, use role ownership:

- `Backend / platform`
- `API engineer`
- `Cloud connector engineer`
- `Endpoint engineer`
- `Detection engineer`
- `PM / founder`

Do not assign one person to everything in the matrix. Even if one person writes most of the code, ownership still needs to be explicit by responsibility.

## Recommended Immediate Sequence

### Step 1

Finish the launch blockers in this order:

1. pipeline T1 + fallback correlation
2. AWS ingest reliability
3. endpoint ingest reliability
4. Azure Event Hub + Entra minimum viable
5. evidence request API
6. CSV/XLSX bulk ingest normalization into the same pipeline
7. self-hosted compose + quickstart

### Step 2

Then tighten quality:

1. persona reports
2. feedback -> factor quality -> suppression / baseline flow
3. T2 gating and queue tuning
4. metrics and dashboards

### Step 3

Then prepare sales/demo:

1. one AWS gold path
2. one Azure gold path
3. one CSV/XLSX backfill path
4. one manager report
5. one evidence-request escalation path

## What We Do Now

Right now, the next practical move is:

1. Treat AWS + endpoint as the first gold path and make it clean.
2. Build Azure only to the minimum viable set listed above.
3. Keep CSV/XLSX as a bulk-ingest front door, but force it through the same canonical T1/T2 logic.
4. Do not start deep forensics or broad cloud parity yet.
5. Build the self-hosted deployment profile and demo around that narrower scope.

## Safe Launch Message

`Janusec is an AWS-first and Azure-minimum self-hosted security sieve for network and endpoint telemetry. It ingests high-volume telemetry, triages deterministically, enriches selectively with local LLMs, reduces false positives through analyst feedback and baselines, and recommends gated forensic follow-up when more evidence is warranted.`

