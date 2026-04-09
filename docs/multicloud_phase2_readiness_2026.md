# Multicloud Phase 2 Readiness

This gate extends the AWS-only realism work into two enterprise variations:

1. `Okta + AWS + Azure`
   - risky Okta sign-in
   - MFA fatigue / impossible travel
   - Azure PIM / storage access
   - AWS AssumeRole / data access

2. `Active Directory + AWS + VMware + Email BEC`
   - suspicious AD authentication
   - VMware administrative task
   - AWS role assumption
   - mailbox-rule and payment-change BEC chain

## What this proves

- Janusec can keep identity, cloud, virtualization, and email evidence in one case.
- Correlation can survive provider boundaries when rows share session, account, host, email identity, IP, and time proximity.
- Persona outputs stay differentiated when the same case contains:
  - identity abuse
  - cloud privilege escalation
  - virtualization change
  - BEC-style communications evidence

## What it does not prove yet

- true live-cloud polling against customer tenants
- long-running multiday backlog recovery
- broker-level Kafka durability under real broker failure
- Flink-class stateful windowing at production throughput

## Queue-backed path before Flink

Recommended progression:

1. `Replay-backed microbatch queue`
   - use Kafka-compatible envelopes
   - measure queue lag, batch latency, throughput, and tenant partitioning

2. `Kafka-backed ingestion`
   - partition by tenant and provider-rich evidence mode
   - preserve bitemporal timestamps and freshness

3. `Flink or equivalent`
   - only when tenant count and event rate justify stateful stream windows beyond worker-batch orchestration

## Closed-beta interpretation

If AWS pressure, multicloud replay, and queue-backed replay remain green together, Janusec is in a credible `design-partner / private closed-beta` posture.

It is still not proof of broad production readiness until:

- live connectors are pressure-tested against real tenants
- tenant-isolation and backlog recovery are tested over longer windows
- queue-backed ingestion is exercised under sustained bursts rather than short deterministic replay windows
