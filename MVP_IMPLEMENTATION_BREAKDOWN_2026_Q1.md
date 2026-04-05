# Janusec MVP Implementation Breakdown 2026 Q1

## Executive Verdict

The direction in [MVP_ACTION_PLAN_2026_Q1.md](C:/AI/janusec/MVP_ACTION_PLAN_2026_Q1.md) is right:

- AWS + Azure first
- network + endpoint first
- deterministic T1 first
- reliable async T2 second
- false-positive reduction first
- on-demand evidence collection as a gated escalation aid
- self-hosted / private-cloud first

That is the correct commercial narrowing.

The plan is also directionally honest, but a few path and status claims need tightening:

- `correlation_emission` is not globally absent. It already exists in multiple correlation rules. The real gap is making sure the event-pipeline path always emits a usable fallback correlation object when rule-level emission is missing.
- `src/connectors/aws/vpc_flow.py` is the wrong path. The real file is [`src/connectors/aws/vpcflow.py`](C:/AI/janusec/src/connectors/aws/vpcflow.py).
- `src/routes/feedback.py` is the wrong path. The real feedback surfaces are [`src/api/routes/feedback.py`](C:/AI/janusec/src/api/routes/feedback.py) and [`src/api/decision_feedback_endpoints.py`](C:/AI/janusec/src/api/decision_feedback_endpoints.py).
- Azure is genuinely behind. The `src/connectors/azure/` package does not exist yet.

The honest launch target is:

`AWS-first, self-hosted network + endpoint security sieve with deterministic T1, selective async T2, persona reports, analyst feedback, and gated evidence follow-up.`

Not:

`fully production-grade multi-cloud autonomous security platform`

## What Is Production-Grade vs Partial vs Stub

### Production-Grade or Close Enough for MVP

- [`src/api/server.py`](C:/AI/janusec/src/api/server.py)
- [`src/api/app.py`](C:/AI/janusec/src/api/app.py)
- [`src/api/stream_ingest.py`](C:/AI/janusec/src/api/stream_ingest.py)
- [`src/core/event_pipeline/pipeline.py`](C:/AI/janusec/src/core/event_pipeline/pipeline.py)
- [`src/core/event_pipeline/stages/primitives.py`](C:/AI/janusec/src/core/event_pipeline/stages/primitives.py)
- [`src/core/event_pipeline/stages/network.py`](C:/AI/janusec/src/core/event_pipeline/stages/network.py)
- [`src/core/correlation/tier1_summarizer.py`](C:/AI/janusec/src/core/correlation/tier1_summarizer.py)
- [`src/queue/redis_tier2.py`](C:/AI/janusec/src/queue/redis_tier2.py)
- [`src/connectors/aws/cloudtrail.py`](C:/AI/janusec/src/connectors/aws/cloudtrail.py)
- [`src/connectors/aws/guardduty.py`](C:/AI/janusec/src/connectors/aws/guardduty.py)
- [`src/connectors/aws/vpcflow.py`](C:/AI/janusec/src/connectors/aws/vpcflow.py)
- [`src/api/report_endpoints.py`](C:/AI/janusec/src/api/report_endpoints.py)

### Partial / Needs Hardening Before Launch

- [`src/connectors/sysmon_evtx.py`](C:/AI/janusec/src/connectors/sysmon_evtx.py)
- [`src/analysis/persona_format.py`](C:/AI/janusec/src/analysis/persona_format.py)
- [`src/api/routes/events.py`](C:/AI/janusec/src/api/routes/events.py)
- [`src/api/routes/feedback.py`](C:/AI/janusec/src/api/routes/feedback.py)
- [`src/api/decision_feedback_endpoints.py`](C:/AI/janusec/src/api/decision_feedback_endpoints.py)
- [`src/core/event_pipeline/stages/advanced.py`](C:/AI/janusec/src/core/event_pipeline/stages/advanced.py)
- [`docker-compose.yml`](C:/AI/janusec/docker-compose.yml)

### Stub / Missing / Roadmap

- `src/connectors/azure/` package
- HTTP-triggered AWS/Azure connector routes
- dedicated evidence-request API for memory / KAPE / PCAP follow-up
- explicit launch-safe feature flagging for unfinished heavy-analysis lanes
- customer-ready self-host deployment docs

## Launch-Safe MVP Scope

### Telemetry Sources

- AWS CloudTrail
- AWS GuardDuty
- AWS VPC Flow or Zeek-style normalized network feeds
- optional AWS SecurityHub
- Windows Sysmon / EVTX-derived endpoint process chains
- auth burst / identity anomaly events
- process lineage events

### Processing Model

- T1 deterministic summary on every alert
- T2 async enrichment only for:
  - high severity
  - ambiguous alerts
  - manager report requests
  - forensics report requests
- selected HEAVY stages only when:
  - confidence is low
  - evidence posture requires it
  - an analyst explicitly requests it

### Output Surfaces

- analyst report
- manager report
- forensics report
- streaming decision feed
- feedback loop:
  - mark legit
  - mark suspicious
  - mark malicious
  - request baseline update

### Deployment

- Docker Compose first
- Ollama local by default
- PostgreSQL
- Redis
- self-hosted or private-cloud first

## Critical Priorities

### CRIT-01: Make the AWS + endpoint gold path complete

Goal:
- ingest
- T1
- T2
- report
- feedback
- no broken gaps

Files to edit:
- [`src/api/routes/events.py`](C:/AI/janusec/src/api/routes/events.py)
- [`src/api/stream_ingest.py`](C:/AI/janusec/src/api/stream_ingest.py)
- [`src/connectors/sysmon_evtx.py`](C:/AI/janusec/src/connectors/sysmon_evtx.py)
- [`src/core/event_pipeline/pipeline.py`](C:/AI/janusec/src/core/event_pipeline/pipeline.py)
- [`src/core/correlation/tier1_summarizer.py`](C:/AI/janusec/src/core/correlation/tier1_summarizer.py)
- [`src/queue/redis_tier2.py`](C:/AI/janusec/src/queue/redis_tier2.py)
- [`src/api/report_endpoints.py`](C:/AI/janusec/src/api/report_endpoints.py)

What to do:
- guarantee every ingested network or endpoint event lands in a canonical envelope
- guarantee T1 is always produced without waiting for LLM or HEAVY stages
- guarantee T2 uses the canonical alert ID and writes back enrichment deterministically
- guarantee reports can render with T1-only or T1+T2 data

### CRIT-02: Fix batching and latency strategy

The workbook samples show why this matters:

- [Cyberstash_csv2.xlsx](C:/AI/janusec/dump/Cyberstash_csv2.xlsx): mixed source sample
- [cybstash csv1.xlsx](C:/AI/janusec/dump/cybstash%20csv1.xlsx): 573-row sheet

Do not run deep analysis across all rows at once.

Files to edit:
- [`src/api/stream_ingest.py`](C:/AI/janusec/src/api/stream_ingest.py)
- [`src/core/event_pipeline/pipeline.py`](C:/AI/janusec/src/core/event_pipeline/pipeline.py)
- [`src/queue/redis_tier2.py`](C:/AI/janusec/src/queue/redis_tier2.py)
- [`src/core/correlation/tier1_summarizer.py`](C:/AI/janusec/src/core/correlation/tier1_summarizer.py)

Recommended operating model:
- ingest chunk size: `100`
- T1 batch size: `10`
- T2 queue batch size: `5`
- max in-flight T2 jobs per tenant: `2-3`
- T1 runs on all alerts
- T2 runs only on clustered top-risk alerts or report requests

### CRIT-03: Ensure fallback `correlation_emission` exists in the event pipeline

Files to edit:
- [`src/core/event_pipeline/pipeline.py`](C:/AI/janusec/src/core/event_pipeline/pipeline.py)
- [`src/core/correlation/tier1_summarizer.py`](C:/AI/janusec/src/core/correlation/tier1_summarizer.py)

What to do:
- if rule-level correlation exists, preserve it
- if it does not, synthesize a minimal fallback:
  - title
  - severity
  - top factors
  - entity keys
  - persona-safe summary
- T1 should never be blocked by missing downstream correlation metadata

### CRIT-04: Add HTTP-triggered connector control plane

Files to create:
- [`src/api/routes/connectors.py`](C:/AI/janusec/src/api/routes/connectors.py)
- [`src/api/scheduler.py`](C:/AI/janusec/src/api/scheduler.py)

Files to edit:
- [`src/api/server.py`](C:/AI/janusec/src/api/server.py)
- [`src/api/app.py`](C:/AI/janusec/src/api/app.py)
- [`src/connectors/aws/cloudtrail.py`](C:/AI/janusec/src/connectors/aws/cloudtrail.py)
- [`src/connectors/aws/guardduty.py`](C:/AI/janusec/src/connectors/aws/guardduty.py)
- [`src/connectors/aws/vpcflow.py`](C:/AI/janusec/src/connectors/aws/vpcflow.py)

What to do:
- add API routes to:
  - trigger a one-off poll
  - view connector health
  - view last checkpoint
  - dry-run or backfill a bounded time window
- add scheduler support for customer-managed polling

### CRIT-05: Bring Azure up to minimum viable speed

Files to create:
- [`src/connectors/azure/__init__.py`](C:/AI/janusec/src/connectors/azure/__init__.py)
- [`src/connectors/azure/base.py`](C:/AI/janusec/src/connectors/azure/base.py)
- [`src/connectors/azure/event_hub.py`](C:/AI/janusec/src/connectors/azure/event_hub.py)
- [`src/connectors/azure/entra_id.py`](C:/AI/janusec/src/connectors/azure/entra_id.py)
- [`src/connectors/azure/defender_cloud.py`](C:/AI/janusec/src/connectors/azure/defender_cloud.py)
- [`src/connectors/azure/normalizer.py`](C:/AI/janusec/src/connectors/azure/normalizer.py)
- [`src/api/routes/azure.py`](C:/AI/janusec/src/api/routes/azure.py)

Files to edit:
- [`src/api/server.py`](C:/AI/janusec/src/api/server.py)
- [`src/api/app.py`](C:/AI/janusec/src/api/app.py)

Minimum Azure launch scope:
- Event Hub consumer
- Entra sign-in logs
- Entra audit logs
- Defender for Cloud normalized ingest

Do not attempt full Azure parity in MVP.

### CRIT-06: Make self-hosted packaging boring and reliable

Files to edit:
- [`docker-compose.yml`](C:/AI/janusec/docker-compose.yml)
- [`README.md`](C:/AI/janusec/README.md)

Files to create:
- [`docker-compose.selfhosted.yml`](C:/AI/janusec/docker-compose.selfhosted.yml)
- [`.env.example`](C:/AI/janusec/.env.example)
- [`docs/SELF_HOSTED_QUICKSTART.md`](C:/AI/janusec/docs/SELF_HOSTED_QUICKSTART.md)

What to do:
- include `ollama`
- include `postgres`
- include `redis`
- make health checks explicit
- document startup order
- document minimum CPU/RAM

## High Priorities

### HIGH-01: Make T1 and T2 summaries reliable and trustable

Files to edit:
- [`src/core/correlation/tier1_summarizer.py`](C:/AI/janusec/src/core/correlation/tier1_summarizer.py)
- [`src/analysis/persona_format.py`](C:/AI/janusec/src/analysis/persona_format.py)
- [`src/api/report_endpoints.py`](C:/AI/janusec/src/api/report_endpoints.py)
- [`src/queue/redis_tier2.py`](C:/AI/janusec/src/queue/redis_tier2.py)

What to do:
- T1 summary must be:
  - deterministic
  - short
  - factor-based
  - reproducible
- T2 must:
  - enrich only selected alerts
  - never override the underlying factors silently
  - separate observed evidence from inferred narrative

### HIGH-02: False-positive reduction loop

Files to edit:
- [`src/api/routes/feedback.py`](C:/AI/janusec/src/api/routes/feedback.py)
- [`src/api/decision_feedback_endpoints.py`](C:/AI/janusec/src/api/decision_feedback_endpoints.py)
- [`src/core/quality/factor_quality.py`](C:/AI/janusec/src/core/quality/factor_quality.py)
- [`src/modules/adaptive_tuner.py`](C:/AI/janusec/src/modules/adaptive_tuner.py)

What to do:
- feedback should update:
  - factor weights
  - suppression rules
  - baseline drift candidates
  - report confidence hints
- ensure the feedback loop actually influences later decisions, not just stores labels

### HIGH-03: Evidence-request API instead of full autonomous forensics

Files to create:
- [`src/api/routes/evidence.py`](C:/AI/janusec/src/api/routes/evidence.py)
- [`src/core/evidence/request_registry.py`](C:/AI/janusec/src/core/evidence/request_registry.py)

Files to edit:
- [`src/api/report_endpoints.py`](C:/AI/janusec/src/api/report_endpoints.py)
- [`src/analysis/persona_format.py`](C:/AI/janusec/src/analysis/persona_format.py)

What to do:
- support requests like:
  - recommend memory capture
  - recommend KAPE collection
  - recommend PCAP retrieval
  - recommend host timeline acquisition
- keep these as:
  - gated
  - analyst-approved
  - auditable

### HIGH-04: Launch-safe feature gating

Files to edit:
- [`src/core/event_pipeline/stages/advanced.py`](C:/AI/janusec/src/core/event_pipeline/stages/advanced.py)
- [`src/api/server.py`](C:/AI/janusec/src/api/server.py)
- [`src/api/app.py`](C:/AI/janusec/src/api/app.py)
- [`docker-compose.yml`](C:/AI/janusec/docker-compose.yml)
- [`.env.example`](C:/AI/janusec/.env.example)

What to do:
- disable by default:
  - partial eBPF
  - binary payload analysis
  - deep PCAP session analysis
  - unfinished external enrichments
  - unfinished advanced synthesis
- expose them only as experimental

### HIGH-05: Operational metrics and launch dashboards

Files to edit:
- [`src/api/server.py`](C:/AI/janusec/src/api/server.py)
- [`src/api/app.py`](C:/AI/janusec/src/api/app.py)

Files to create:
- [`grafana/dashboards/mvp_ingest.json`](C:/AI/janusec/grafana/dashboards/mvp_ingest.json)
- [`grafana/dashboards/mvp_pipeline.json`](C:/AI/janusec/grafana/dashboards/mvp_pipeline.json)
- [`grafana/dashboards/mvp_feedback.json`](C:/AI/janusec/grafana/dashboards/mvp_feedback.json)

Metrics to expose:
- ingest throughput
- T1 latency
- T2 queue lag
- T2 failure rate
- connector poll success
- report generation success
- false-positive decisions by factor

## Medium Priorities

### MED-01: Persona report improvement

Files to edit:
- [`src/analysis/persona_format.py`](C:/AI/janusec/src/analysis/persona_format.py)
- [`src/api/report_endpoints.py`](C:/AI/janusec/src/api/report_endpoints.py)

Improve:
- analyst report: evidence-first
- manager report: impact-first
- forensics report: acquisition-first

### MED-02: Private-cloud deployment profiles

Files to create:
- [`docs/DEPLOYMENT_VM.md`](C:/AI/janusec/docs/DEPLOYMENT_VM.md)
- [`docs/DEPLOYMENT_NUTANIX.md`](C:/AI/janusec/docs/DEPLOYMENT_NUTANIX.md)
- [`docs/DEPLOYMENT_PRIVATE_CLOUD.md`](C:/AI/janusec/docs/DEPLOYMENT_PRIVATE_CLOUD.md)

Recommended deployment targets:
- single customer VM
- private cloud on Nutanix / VMware
- small on-prem cluster

Avoid making NAS-style deployment the core enterprise story. It is fine for PoC, not the primary production positioning.

### MED-03: Self-hosted sales proof pack

Files to create:
- [`docs/MVP_DEMO_SCRIPT.md`](C:/AI/janusec/docs/MVP_DEMO_SCRIPT.md)
- [`docs/MVP_LIMITATIONS.md`](C:/AI/janusec/docs/MVP_LIMITATIONS.md)
- [`docs/MVP_SALES_POSITIONING.md`](C:/AI/janusec/docs/MVP_SALES_POSITIONING.md)

## Low Priorities

- GCP parity
- deep eBPF monitoring
- binary payload analysis
- autonomous evidence collection
- Kubernetes / Helm
- broad multi-tenant SaaS packaging

## Recommended Phase Plan

### Phase 0: Launch-Safe Narrowing

Duration:
- 2-3 days

Goals:
- disable partial features by default
- define the AWS + Azure + network + endpoint MVP perimeter
- document what is in and out

Deliverables:
- feature flags
- MVP limitations doc
- self-host compose baseline

### Phase 1: Sellable MVP

Duration:
- 1-2 weeks

Goals:
- AWS ingest fully reliable
- endpoint ingest fully reliable
- T1 always-on
- T2 async selective
- persona reports reliable
- feedback loop works
- evidence request API exists

Deliverables:
- ingest -> T1 -> T2 -> report gold path
- analyst feedback loop
- manager/forensics reports
- Docker Compose self-host deployment

### Phase 2: Azure Minimum Viable

Duration:
- 1 week

Goals:
- Event Hub consumer
- Entra logs
- Defender Cloud normalized path
- Azure connector health and scheduling

Deliverables:
- Azure ingest demo
- Azure report example
- Azure connector docs

### Phase 3: Hardening and Expansion

Duration:
- 1-2 weeks

Goals:
- lower false positives
- better dashboards
- better baselines
- safer heavy-stage usage
- stronger self-host runbooks

Deliverables:
- operational dashboards
- launch checklist
- tuned factor weights
- cleaner T2 quality

## Self-Hosted / Private-Cloud Deployment Guidance

### Best Fast-Deploy Options

#### Option A: Single VM

Best for:
- PoC
- first customer pilot
- internal demo

Stack:
- api
- worker
- ollama
- postgres
- redis

Recommended sizing:
- 4 vCPU minimum
- 8-16 GB RAM
- SSD storage

#### Option B: Nutanix / Private Cloud VM

Best for:
- enterprise pilot
- compliance-focused customer
- regulated environment

Why:
- easy customer story
- private control plane
- no SaaS objection
- fast procurement path

#### Option C: Small On-Prem Cluster

Best for:
- customer with existing virtual infrastructure
- higher event volume

Do not overcomplicate this with Kubernetes in MVP.

## CEO Video: What To Show

Show exactly one strong gold path:

1. ingest AWS or network telemetry
2. immediate deterministic T1 summary
3. selective async T2 enrichment
4. analyst report
5. manager report
6. evidence request recommendation
7. feedback action
8. dashboard showing connector and queue health

Do not show:
- unfinished Azure breadth
- deep forensics that are not reliable
- advanced heavy stages that are still partial

## Honest Sales Positioning

Safe claim:

`Janusec is an AWS-first, self-hosted security sieve for network and endpoint telemetry. It triages deterministically, enriches selectively with local LLMs, reduces false positives through feedback and baselines, and generates persona-specific reports with gated evidence follow-up.`

Unsafe claim:

`Janusec is already a complete production-grade multi-cloud autonomous SOC platform.`

## Immediate Next Steps

1. Fix the event-pipeline T1 / fallback correlation path in [`src/core/event_pipeline/pipeline.py`](C:/AI/janusec/src/core/event_pipeline/pipeline.py).
2. Add connector control routes and scheduler.
3. Add Azure minimum viable ingest package.
4. Wire Sysmon endpoint events cleanly through canonical ingest.
5. Make feedback influence later scoring and baselines.
6. Add evidence-request API.
7. Add self-host Compose profile and docs.

