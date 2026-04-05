# Janusec Production Readiness Next Steps (2026 Q1)

## Scope

This document reflects the current narrowed product direction:

- AWS + Azure first
- Network + endpoint first
- Deterministic T1 first
- Selective async T2 second
- False-positive reduction before domain expansion
- On-demand evidence requests before autonomous collection
- Self-hosted / private-cloud first

## What Was Hardened In This Slice

- Tier 2 now fails closed in live mode when no provider is available instead of returning fake placeholder output.
- Graph/session enrichment now fails closed in live mode when LLM enrichment is unavailable.
- Demo factor injection is disabled in live mode.
- Connector runtime status now exposes:
  - checkpoint
  - duplicate suppression count
  - latency
  - runtime state
  - circuit-open state
- Minimal operator runtime surface added:
  - `frontend/static/connectors_runtime.html`

## What Live Testing Must Happen Before Real Cloud Resources

### 1. Live AWS Tenant Validation

Run against real:

- CloudTrail
- GuardDuty
- SecurityHub
- VPC Flow Logs

Validate:

- credentials and auth failure paths
- first poll succeeds
- pagination / continuation
- checkpoint persistence
- restart and resume
- duplicate suppression
- malformed event handling
- latency stays bounded
- no silent event drops

### 2. Live Azure Tenant Validation

Run against real:

- Event Hub
- Entra ID Sign-In Logs
- Entra ID Audit Logs
- Defender for Cloud

Validate:

- tenant/client secret config
- Event Hub consumer start position
- Entra pagination / query window correctness
- checkpoint persistence
- restart and resume
- duplicate suppression
- auth failure / token refresh failures
- malformed event handling

### 3. Replay / Soak Validation

Use large corpora for:

- VPC Flow
- Event Hub
- mixed IAM + network + endpoint

Minimum targets:

- 10k+ events per source
- 1h sustained ingest
- repeated worker restart
- no duplicate storm
- no checkpoint regression
- queue lag does not grow without bound

### 4. False-Positive Validation

Build labeled replay sets:

- benign admin IAM changes
- benign service principal churn
- benign sign-in bursts
- benign east-west network traffic
- malicious IAM abuse
- suspicious egress
- cloud + endpoint overlap attack sequences

Track:

- T1 precision
- suppression hit rate
- duplicate suppression rate
- escalation rate
- T2 trigger rate

## Remaining Demo / Stub / Partial Paths

These still block a full production-grade claim and should either be fixed or explicitly disabled outside dev/test:

- `src/domains/binary/dynamic_analyzer.py`
  - demo / placeholder dynamic binary analysis
- `src/soar/playbook_engine.py`
  - placeholder downstream actioning
- `src/api/automation_endpoints.py`
  - placeholder SOAR control paths
- `src/api/graph_sessions.py`
  - contains deterministic/demo-style summary behavior that should be reviewed before production exposure
- `src/api/deep_analyze_endpoints.py`
  - still contains lite-mode / placeholder behavior
- `src/api/ebpf_endpoints.py`
  - not production-grade endpoint telemetry depth
- `src/enrichment/cve_lookup.py`
  - offline/demo-oriented lookup behavior still needs review for production mode
- `src/enrichment/lookup_registry.py`
  - synthetic/demo enrichment behavior still needs review

## Critical Priorities

1. Real AWS tenant integration harness
2. Real Azure tenant integration harness
3. T1 suppression / baseline tuning for IAM and network
4. Restart recovery validation
5. Soak tests for VPC / Event Hub
6. Remove or hard-disable remaining live-path placeholders in T2 / graph / deep-analyze
7. Operator runtime truth surfaces for connector config, health, checkpoint, circuit-open, duplicates

## High Priorities

1. HopGraph scoring for:
   - same actor across AWS/Azure
   - same IP across sign-in and flow logs
   - same resource/account across cloud and endpoint evidence
2. Replay corpus suite with labeled benign and malicious sets
3. Endpoint + cloud overlap tuning
4. Stronger health semantics and alerting
5. Evidence-request workflow for SOC / threat hunters
6. Self-hosted deployment hardening and install docs

## Medium Priorities

1. Policy-as-code for tenant-specific routing / suppression
2. Deeper identity coverage
3. Cleaner analyst / manager / forensics reporting
4. DevSecOps CI reliability and packaging
5. Better explanation quality for correlated alerts

## Low Priorities For Current MVP

- deeper eBPF
- deep PCAP session analysis
- binary sandbox sophistication
- broad SOAR automation
- GCP expansion
- wider telemetry-domain expansion

## Recommended Order Of Work

### Phase 1: Truth And Stability

- run live AWS and Azure connector validation
- fix auth / paging / checkpoint / restart issues
- stabilize runtime health reporting

### Phase 2: Signal Quality

- tune T1 suppression
- tune baselines
- measure false positives
- improve HopGraph overlap scoring

### Phase 3: Operational Confidence

- soak tests
- restart tests
- duplicate suppression tests
- alerting
- self-hosted docs and hardening

### Phase 4: Controlled Expansion

- deeper identity
- deeper endpoint
- evidence request workflow
- selected deep-analysis improvements

## Current Honest Positioning

Safe to claim now:

- AWS/Azure connector foundation is real
- unified connector control plane is real
- deterministic T1 and selective T2 direction is real
- operator runtime truth is improving

Not yet safe to claim:

- fully production-grade multi-cloud investigation platform
- fully production-grade deep endpoint / binary / eBPF / PCAP coverage
- complete SOAR automation

## Immediate Next Command Set

1. Run live tenant integration against AWS and Azure.
2. Run replay / soak tests at larger volume.
3. Tune T1 until false positives are acceptable.
4. Tighten HopGraph multi-cloud scoring.
5. Remove or hard-disable remaining placeholder/deep-demo paths.
6. Only then expand domains.
