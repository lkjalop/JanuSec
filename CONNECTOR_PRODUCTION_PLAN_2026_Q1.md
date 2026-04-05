# Janusec Connector Production Plan 2026 Q1

## Objective

Get the AWS and Azure connector layer production-ready first, then run a full capability and reliability test sweep before adding more domains or deeper analysis.

The immediate product focus is:

- AWS first
- Azure minimum viable second
- network + endpoint first
- identity correlation first
- deterministic T1 first
- reliable async T2 second
- false-positive reduction first
- self-hosted / private-cloud first

## Current Honest State

### AWS

#### Real / Reusable Today

- [`src/connectors/aws/cloudtrail.py`](C:/AI/janusec/src/connectors/aws/cloudtrail.py)
  - real connector class exists
  - incremental fetch idea exists
  - checkpoint logic exists

- [`src/connectors/aws/guardduty.py`](C:/AI/janusec/src/connectors/aws/guardduty.py)
  - real connector class exists
  - detector lookup and finding fetch logic exists

- [`src/connectors/aws/securityhub.py`](C:/AI/janusec/src/connectors/aws/securityhub.py)
  - real connector skeleton exists
  - finding fetch logic exists

- [`src/collectors/iam_aws_worker.py`](C:/AI/janusec/src/collectors/iam_aws_worker.py)
  - AWS IAM collector exists
  - CloudTrail polling flow exists for IAM events

#### Not Production-Ready Yet

- [`src/connectors/aws/vpcflow.py`](C:/AI/janusec/src/connectors/aws/vpcflow.py)
  - still placeholder
  - no real S3 / CloudWatch pull logic

- [`src/api/connectors_cloudtrail.py`](C:/AI/janusec/src/api/connectors_cloudtrail.py)
  - current route ingests payloads pushed into it
  - it is not a true connector control plane

- [`src/api/status_connectors.py`](C:/AI/janusec/src/api/status_connectors.py)
  - explicitly stubbed

### Azure

#### Real / Reusable Today

- [`src/api/iam_ingest_endpoints.py`](C:/AI/janusec/src/api/iam_ingest_endpoints.py)
  - Azure webhook route exists
  - Azure poll route exists
  - AzureADCollector hook exists if dependency is available

- [`src/api/iam_connector_endpoints.py`](C:/AI/janusec/src/api/iam_connector_endpoints.py)
  - already contains Azure/Entra-facing admin/config surface

#### Not Production-Ready Yet

- There is no `src/connectors/azure/` package
- Azure is still mixed into IAM ingest rather than represented as a first-class connector family
- no clean Event Hub connector module
- no clean Entra sign-in / audit connector module
- no clean Defender for Cloud connector module

## Recommended Source Priority

### AWS

1. CloudTrail
2. GuardDuty
3. VPC Flow Logs
4. SecurityHub

### Azure

1. Entra ID Sign-In Logs
2. Entra ID Audit Logs
3. Event Hub
4. Defender for Cloud or Defender XDR export path

## Why These Sources Matter for Correlation

These are the first sources that let HopGraph correlate:

- `principal`
  - AWS IAM identity
  - Azure Entra identity

- `control-plane`
  - API changes
  - role changes
  - policy changes

- `network`
  - egress
  - beaconing
  - unusual connections

- `endpoint`
  - process lineage
  - auth-linked execution

The first high-value graph stories are:

1. `Account misuse`
- sign-in anomaly or CloudTrail auth event
- plus role / token / app change
- plus endpoint or network confirmation

2. `Privilege change + suspicious activity`
- CloudTrail or Entra audit change
- plus GuardDuty / Defender
- plus VPC Flow or Sysmon evidence

3. `IOC reuse across identities and assets`
- same IP
- same domain
- same user
- same process hash

## Critical Work

### CRIT-01: Productionize AWS connector modules

Files to edit:
- [`src/connectors/aws/cloudtrail.py`](C:/AI/janusec/src/connectors/aws/cloudtrail.py)
- [`src/connectors/aws/guardduty.py`](C:/AI/janusec/src/connectors/aws/guardduty.py)
- [`src/connectors/aws/securityhub.py`](C:/AI/janusec/src/connectors/aws/securityhub.py)
- [`src/connectors/aws/vpcflow.py`](C:/AI/janusec/src/connectors/aws/vpcflow.py)

What to do:
- standardize checkpoint model
- standardize canonical envelope fields
- standardize fetch window / cursor handling
- standardize error handling and health snapshots

Done means:
- all four connectors support bounded fetch
- checkpoint save/load works
- canonical envelopes include stable entity keys
- connector health reports are real, not inferred

### CRIT-02: Replace stub connector health with real per-connector state

Files to edit:
- [`src/api/status_connectors.py`](C:/AI/janusec/src/api/status_connectors.py)
- [`src/api/runtime_state.py`](C:/AI/janusec/src/api/runtime_state.py)
- [`src/api/ingestion_health.py`](C:/AI/janusec/src/api/ingestion_health.py)

What to do:
- remove hard-coded placeholders
- report:
  - last poll time
  - last successful fetch
  - last error
  - last ingested count
  - checkpoint age
  - queue depth

Done means:
- status API reflects actual AWS/Azure connector runtime state

### CRIT-03: Create a real AWS/Azure connector control plane

Files to create:
- [`src/api/routes/connectors.py`](C:/AI/janusec/src/api/routes/connectors.py)

Files to edit:
- [`src/api/server.py`](C:/AI/janusec/src/api/server.py)
- [`src/api/app.py`](C:/AI/janusec/src/api/app.py)
- [`src/api/connectors_cloudtrail.py`](C:/AI/janusec/src/api/connectors_cloudtrail.py)
- [`src/api/connectors_sysmon.py`](C:/AI/janusec/src/api/connectors_sysmon.py)

What to do:
- unify:
  - poll now
  - health
  - checkpoint
  - backfill
  - last error

Done means:
- customers and tests can drive connectors without CLI-only paths

### CRIT-04: Build first-class Azure connector package

Files to create:
- [`src/connectors/azure/__init__.py`](C:/AI/janusec/src/connectors/azure/__init__.py)
- [`src/connectors/azure/base.py`](C:/AI/janusec/src/connectors/azure/base.py)
- [`src/connectors/azure/event_hub.py`](C:/AI/janusec/src/connectors/azure/event_hub.py)
- [`src/connectors/azure/entra_id.py`](C:/AI/janusec/src/connectors/azure/entra_id.py)
- [`src/connectors/azure/defender_cloud.py`](C:/AI/janusec/src/connectors/azure/defender_cloud.py)
- [`src/connectors/azure/normalizer.py`](C:/AI/janusec/src/connectors/azure/normalizer.py)

Files to edit:
- [`src/api/iam_ingest_endpoints.py`](C:/AI/janusec/src/api/iam_ingest_endpoints.py)
- [`src/api/iam_connector_endpoints.py`](C:/AI/janusec/src/api/iam_connector_endpoints.py)

What to do:
- move Azure from mixed IAM-only special handling into a proper connector family
- preserve existing IAM routes as compatibility wrappers if needed

Done means:
- Azure sources can be polled and normalized the same way AWS connectors can

### CRIT-05: Implement real VPC Flow ingestion

Files to edit:
- [`src/connectors/aws/vpcflow.py`](C:/AI/janusec/src/connectors/aws/vpcflow.py)

What to do:
- choose one production path first:
  - S3-backed VPC Flow delivery
  - or CloudWatch Logs pull
- normalize:
  - source IP
  - destination IP
  - source port
  - destination port
  - action
  - bytes/packets
  - account / VPC / subnet / ENI

Done means:
- VPC Flow connector yields real network primitives into the pipeline

## High Work

### HIGH-01: Standardize canonical envelope for cloud + endpoint + IAM

Files to edit:
- [`src/connectors/aws/base.py`](C:/AI/janusec/src/connectors/aws/base.py)
- [`src/connectors/sysmon_evtx.py`](C:/AI/janusec/src/connectors/sysmon_evtx.py)
- [`src/api/iam_ingest_endpoints.py`](C:/AI/janusec/src/api/iam_ingest_endpoints.py)
- future [`src/connectors/azure/normalizer.py`](C:/AI/janusec/src/connectors/azure/normalizer.py)

Required fields:
- tenant_id
- source_family
- source_type
- ts
- severity
- entity.principal
- entity.host
- entity.ip
- entity.domain
- entity.account
- raw_ref or raw digest

### HIGH-02: Wire connectors into the same T1/T2 pipeline

Files to edit:
- [`src/core/event_pipeline/pipeline.py`](C:/AI/janusec/src/core/event_pipeline/pipeline.py)
- [`src/api/stream_ingest.py`](C:/AI/janusec/src/api/stream_ingest.py)
- [`src/api/routes/events.py`](C:/AI/janusec/src/api/routes/events.py)
- [`src/api/csv_endpoints.py`](C:/AI/janusec/src/api/csv_endpoints.py)
- [`src/api/csv_multi_endpoints.py`](C:/AI/janusec/src/api/csv_multi_endpoints.py)

What to do:
- AWS
- Azure
- Sysmon
- CSV/XLSX bulk uploads
all land into the same event envelope and same triage path

### HIGH-03: Add connector-specific regression and contract tests

Files to create:
- [`tests/connectors/test_cloudtrail_connector.py`](C:/AI/janusec/tests/connectors/test_cloudtrail_connector.py)
- [`tests/connectors/test_guardduty_connector.py`](C:/AI/janusec/tests/connectors/test_guardduty_connector.py)
- [`tests/connectors/test_securityhub_connector.py`](C:/AI/janusec/tests/connectors/test_securityhub_connector.py)
- [`tests/connectors/test_vpcflow_connector.py`](C:/AI/janusec/tests/connectors/test_vpcflow_connector.py)
- [`tests/connectors/test_azure_event_hub_connector.py`](C:/AI/janusec/tests/connectors/test_azure_event_hub_connector.py)
- [`tests/connectors/test_azure_entra_connector.py`](C:/AI/janusec/tests/connectors/test_azure_entra_connector.py)
- [`tests/connectors/test_defender_cloud_connector.py`](C:/AI/janusec/tests/connectors/test_defender_cloud_connector.py)
- [`tests/api/test_connector_control_plane.py`](C:/AI/janusec/tests/api/test_connector_control_plane.py)

Done means:
- every connector has:
  - normalization test
  - pagination/checkpoint test
  - empty fetch test
  - failure handling test

### HIGH-04: Full suite source validation using sample and synthetic telemetry

Files to create:
- [`tests/integration/test_aws_ingest_pipeline.py`](C:/AI/janusec/tests/integration/test_aws_ingest_pipeline.py)
- [`tests/integration/test_azure_ingest_pipeline.py`](C:/AI/janusec/tests/integration/test_azure_ingest_pipeline.py)
- [`tests/integration/test_identity_network_correlation.py`](C:/AI/janusec/tests/integration/test_identity_network_correlation.py)

Done means:
- source -> normalize -> pipeline -> T1 -> T2 -> report works

## Medium Work

### MED-01: SecurityHub and Defender report shaping

Files to edit:
- [`src/analysis/persona_format.py`](C:/AI/janusec/src/analysis/persona_format.py)
- [`src/api/report_endpoints.py`](C:/AI/janusec/src/api/report_endpoints.py)

Goal:
- manager reports explain cloud findings without SOC-only jargon

### MED-02: Backfill and bounded time-window controls

Files to edit:
- [`src/api/routes/connectors.py`](C:/AI/janusec/src/api/routes/connectors.py)
- [`src/connectors/aws/cloudtrail.py`](C:/AI/janusec/src/connectors/aws/cloudtrail.py)
- [`src/connectors/aws/guardduty.py`](C:/AI/janusec/src/connectors/aws/guardduty.py)
- future Azure connector files

Goal:
- support:
  - last 15m
  - last 1h
  - last 24h
  - backfill since cursor

### MED-03: Metrics and flakiness detection

Files to edit:
- [`src/api/metrics_endpoints.py`](C:/AI/janusec/src/api/metrics_endpoints.py)
- [`src/api/status_connectors.py`](C:/AI/janusec/src/api/status_connectors.py)

Metrics to add:
- connector fetch success rate
- connector fetch latency
- checkpoint freshness
- empty poll rate
- normalization failure rate
- T1 latency by source
- T2 queue lag by source

## Low Work

- GCP parity
- deep PCAP
- eBPF depth
- binary payload analysis
- autonomous evidence collection

## Test Strategy Before More Enhancements

### Phase A: Connector Unit and Contract Tests

Run first:
- connector fetchers
- pagination
- checkpointing
- normalization
- failure handling

### Phase B: Pipeline Integration Tests

Run second:
- AWS sources through T1
- Azure sources through T1
- selected T2 path
- report generation

### Phase C: Reliability and Flakiness Tests

Run third:
- repeated poll cycles
- restart/recovery
- empty source windows
- malformed events
- duplicate events
- partial connector outages

### Phase D: False-Positive and Correlation Validation

Run fourth:
- IAM anomaly + network link
- identity + endpoint link
- GuardDuty + CloudTrail link
- Entra audit + sign-in link

## What We Do Now

1. Productionize the four AWS connectors.
2. Build the Azure connector package to minimum viable.
3. Replace stub connector status with real runtime health.
4. Add a unified connector control plane.
5. Run unit + contract tests on AWS and Azure sources.
6. Run full T1/T2 pipeline integration tests.
7. Only after that, decide what broader hardening or domain expansion comes next.

## Immediate Order

### Week 1

- CloudTrail
- GuardDuty
- SecurityHub
- VPC Flow
- connector status

### Week 2

- Azure Event Hub
- Entra sign-in
- Entra audit
- Defender for Cloud
- connector control routes

### Week 3

- connector test suite
- integration suite
- flakiness/restart tests
- false-positive tuning

## Honest Verdict

Yes, focusing on production-grade AWS and Azure connectors first is the right call.

The repo already has enough AWS and IAM/Azure scaffolding to make this tractable quickly, but it is not yet honest to call the connector layer production-grade.

The biggest concrete gaps are:

- VPC Flow is still placeholder
- Azure is not yet a first-class connector family
- connector status is stubbed
- CloudTrail API route is push-ingest, not a proper poll/control surface

Fix those first, then test the full Janusec capability honestly before adding more scope.

