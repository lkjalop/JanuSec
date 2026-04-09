# Kafka Live Ingest, Soak, and Pressure Guidance

## Current State
- A dedicated Kafka-backed assessment lane now exists in code:
  - request topic: `janusec.assessment.requests`
  - result topic: `janusec.assessment.results`
  - tenant-keyed partition hinting via `tenant_id`
  - worker fan-out via `src/workers/kafka_assessment_worker.py`
- Accelerated soak coverage now includes:
  - enterprise dual-firewall + CDN posture
  - zero-firewall posture
  - ransomware-style encryption burst
  - no-CDN DDoS / origin saturation burst
  - benign marketing overload

## What This Proves
- Janusec can be pressure-tested against realistic replay-backed backlog and burst patterns.
- Tenant-keyed partitioning and worker fan-out are in place for real Kafka adoption.
- Benign vs malicious overload can be tested explicitly instead of hand-waving the difference.

## What This Does Not Yet Prove
- It does not prove production readiness for true always-on customer traffic.
- It does not prove live connector fidelity without approved, disposable credentials.
- It does not replace a real 12-24h soak against a durable Kafka broker and persistent worker fleet.

## Recommended Validation Ladder
1. Accelerated replay soak in CI/dev.
2. 12-24h Kafka-backed soak with backlog recovery and tenant isolation metrics.
3. 3-day accelerated soak once queue lag and dedupe remain stable.
4. 7-day endurance soak only after the 24h and 3-day gates stay green.
5. Disposable live validations:
   - Okta + AWS + Azure
   - AD/Entra + VMware or Nutanix + Exchange/M365

## Scaling Path
1. Vertical scaling:
   - more worker concurrency
   - smaller batch sizes
   - reduced parallel UI noise
2. Durable queue scaling:
   - Kafka tenant partitioning
   - worker fan-out
   - backlog and dedupe metrics
3. Stream-processing later:
   - only consider Flink-class stateful streaming after live multi-tenant traffic justifies the complexity

## Pressure Cases to Keep in the Release-Candidate Wringer
- Ransomware-style encryption plus containment simulation
- No-CDN DDoS and origin saturation
- Benign marketing traffic burst
- Compromised MFA and temporary privilege abuse
- Policy drift and approved-change false-positive suppression
- Crisis-management and compliance-control impact rendering

## Honest Beta Readiness Interpretation
- Good enough for serious private alpha / design-partner validation once the 12-24h soak is green.
- Not honest to call broad customer-facing closed beta until:
  - durable Kafka soak is green
  - queue lag is materially reduced under burst
  - disposable live validations succeed
