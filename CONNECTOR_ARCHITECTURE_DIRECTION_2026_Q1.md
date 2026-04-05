# Janusec Connector-First Architecture Direction 2026 Q1

## Executive Verdict

Janusec should launch as an AWS-first, Azure-minimum, self-hosted security sieve focused on:

- network telemetry
- endpoint telemetry
- IAM / account activity correlation
- deterministic T1 triage on every alert
- selective async T2 enrichment on the minority of alerts that justify it
- gated evidence requests instead of default autonomous forensics

This is the strongest production-grade path because it:

- narrows scope to the telemetry sources customers already trust
- reduces false positives before adding more domains
- gives SOC and threat hunters usable output quickly
- keeps the product deployable in private cloud / customer-controlled environments

## What Is Real Now

The current codebase now has a more credible connector foundation for:

- AWS CloudTrail
- AWS GuardDuty
- AWS SecurityHub
- AWS VPC Flow Logs
- Azure Event Hub
- Azure Entra sign-in
- Azure Entra audit
- Azure Defender for Cloud

The following foundational capabilities are now wired:

- per-connector checkpoints
- runtime connector health
- unified connector poll/backfill/status routes
- persisted per-tenant connector configuration
- retry/backoff and circuit-state handling for connector polls
- duplicate suppression across repeated connector polls
- normalized envelopes for AWS and Azure sources
- correlation keys on AWS and Azure events for cross-cloud pivots
- runtime status summary route
- tests for AWS/Azure connector primitives and connector control plane

## What Is Production Grade vs Partial

### Production Grade Enough To Build On

- connector checkpoint persistence
- checkpoint resume verification in tests
- runtime connector health tracking
- unified connector control plane routing
- persisted Azure connector config
- duplicate suppression across repeated polls
- retry/backoff/circuit-state execution wrapper
- AWS CloudTrail polling foundation
- AWS GuardDuty polling foundation
- AWS SecurityHub polling foundation
- Azure Event Hub connector foundation
- Azure Entra sign-in / audit connector foundation
- Azure Defender for Cloud connector foundation
- status APIs for connector runtime visibility
- cross-cloud correlation keys for AWS + Azure identity/network pivots

### Real But Still Needs Hardening

- AWS VPC Flow path: useful now, but still needs volume and token/resume hardening
- Azure Event Hub: needs real tenant auth/configuration lifecycle and more field validation
- Azure Entra / Defender polling: good core shape, but needs production backoff, retries, and auth handling
- connector control plane: correct architecture now, but still needs stronger operator/UI integration
- false-positive controls: architecture supports them, but more tuning is still required in detection/correlation layers

### Still Partial / Not Launch Headline

- deep endpoint forensics automation
- default autonomous memory/KAPE/pcap acquisition
- binary payload depth
- eBPF depth
- broad multi-cloud parity beyond AWS + minimum Azure

## New Direction

### Core Product Statement

Janusec is a self-hosted cloud-and-endpoint security sieve that:

1. ingests AWS and Azure security telemetry plus endpoint/network events
2. normalizes those events into a common envelope
3. runs deterministic T1 triage immediately
4. selectively runs async T2 enrichment on high-risk or ambiguous alerts
5. correlates identity, network, cloud, and endpoint evidence into a HopGraph incident view
6. emits analyst, manager, and forensics-ready reports
7. recommends gated follow-up evidence requests instead of default autonomous deep collection

## Left-to-Right Architecture

```text
+------------------+    +---------------------+    +------------------------+
| AWS Sources      |    | Azure Sources       |    | Endpoint / Network     |
|------------------|    |---------------------|    |------------------------|
| CloudTrail       |    | Event Hub           |    | Sysmon / WEF           |
| GuardDuty        |    | Entra Sign-In Logs  |    | Zeek / VPC Flow        |
| SecurityHub      |    | Entra Audit Logs    |    | EDR / XDR exports      |
| VPC Flow Logs    |    | Defender for Cloud  |    | Auth / process lineage |
+---------+--------+    +----------+----------+    +-----------+------------+
          |                          |                           |
          +------------+-------------+-------------+-------------+
                       |                           |
                       v                           v
             +--------------------------------------------------+
             | Ingest Adapters / Connector Control Plane        |
             |--------------------------------------------------|
             | poll | webhook | backfill | status | checkpoint  |
             | config | retry | circuit | duplicate suppression |
             +---------------------------+----------------------+
                                         |
                                         v
             +--------------------------------------------------+
             | Canonical Event Normalization                    |
             |--------------------------------------------------|
             | source mapping | tenant tagging | ts parsing     |
             | IAM fields     | network fields | endpoint fields|
             +---------------------------+----------------------+
                                         |
                                         v
             +--------------------------------------------------+
             | T1 Deterministic Triage                          |
             |--------------------------------------------------|
             | fast rules | baseline checks | dedupe           |
             | confidence | priority | initial action         |
             +---------------------------+----------------------+
                                         |
                    +--------------------+--------------------+
                    |                                         |
                    v                                         v
       +---------------------------+             +-----------------------------+
       | HopGraph Correlation      |             | T2 Async Enrichment         |
       |---------------------------|             |-----------------------------|
       | account drift             |             | only high-risk / ambiguous  |
       | auth anomalies            |             | report requests             |
       | endpoint + IAM joins      |             | LLM narrative               |
       | network + cloud joins     |             | hunt guidance               |
       +-------------+-------------+             +-------------+---------------+
                     |                                           |
                     +-------------------+-----------------------+
                                         |
                                         v
             +--------------------------------------------------+
             | Output Layer                                     |
             |--------------------------------------------------|
             | analyst report | manager report | forensic report|
             | push/notify    | mark legit/malicious            |
             | evidence request recommendation                  |
             +---------------------------+----------------------+
                                         |
                                         v
             +--------------------------------------------------+
             | Human Investigation / Gated Follow-Up            |
             |--------------------------------------------------|
             | request pcap | request memory | request KAPE     |
             | approve baseline update | ticket / case handling |
             +--------------------------------------------------+
```

## User Flows

### 1. SOC Analyst Flow

```text
alert arrives
  -> connector normalizes event
  -> T1 triage scores it
  -> HopGraph links related cloud/network/endpoint evidence
  -> T2 runs only if alert is severe or ambiguous
  -> analyst sees:
       what happened
       why it matters
       what else overlaps
       what to request next
  -> analyst marks:
       legit / suspicious / malicious
```

### 2. Threat Hunter Flow

```text
batch of telemetry uploaded or polled
  -> T1 clusters suspicious alerts
  -> HopGraph identifies shared domains, users, IPs, processes, accounts
  -> T2 generates hunt leads only for top clusters
  -> hunter pivots:
       same account
       same IP
       same process lineage
       same destination / infrastructure
  -> hunter decides whether deeper telemetry is justified
```

### 3. Security Manager Flow

```text
many alerts land in queue
  -> T1 reduces noisy alerts
  -> only highest-risk incidents get enriched
  -> manager report summarizes:
       severity
       blast radius
       business impact
       confidence
       recommended next action
  -> manager approves:
       escalation
       evidence collection
       containment recommendation
```

### 4. Private-Cloud Customer Flow

```text
customer deploys Janusec in private cloud
  -> configures AWS + Azure connectors
  -> sends endpoint/network telemetry
  -> Janusec keeps raw data inside customer environment
  -> local Ollama handles T2 by default
  -> SOC uses reports + feedback loop
  -> only approved evidence requests go deeper
```

## Why Companies Would Want This

- keeps telemetry and enrichment inside customer-controlled infrastructure
- reduces analyst fatigue by suppressing or downgrading low-value alerts early
- provides identity + network + endpoint correlation in one path
- gives managers short, usable reports instead of raw telemetry
- avoids over-automating destructive or invasive forensic actions
- works as a security middleware layer instead of forcing a full SOC platform replacement

## Pros

- self-hosted story is strong for regulated buyers
- AWS + Azure minimum is commercially relevant
- T1-first model is faster, cheaper, and more reliable
- selective T2 makes LLM usage defensible
- HopGraph correlation gives a stronger narrative than isolated alerts
- gated evidence requests align with real SOC workflows

## Cons

- not yet full multi-cloud parity
- not yet deep autonomous forensics
- requires careful false-positive tuning per tenant
- private-cloud deployment still needs polished quickstart and ops docs
- Azure story is now viable, but still newer than AWS in overall maturity

## Current Priorities

### Critical

1. Harden AWS connector reliability.
2. Harden Azure connector authentication, retries, and backfill behavior.
3. Keep all sources flowing into one canonical event path.
4. Improve T1 false-positive reduction before adding new domains.
5. Ensure T2 only runs for justified alerts.
6. Add strong connector health and checkpoint observability.

### High

1. Tune HopGraph joins around IAM, network, and endpoint overlap.
2. Improve analyst feedback loops and baseline update workflows.
3. Package self-hosted deployment for customer pilot speed.
4. Add restart/resume and flaky-source resilience.

### Medium

1. Expand Azure depth after minimum viable sources stabilize.
2. Improve UI/reporting for connector control and status.
3. Add more contract tests and replay packs.

### Low

1. Expand beyond AWS + Azure before the core path is stable.
2. Re-introduce deeper endpoint forensics as a default action.
3. Chase broader multi-domain scope before false positives are under control.

## What To Do Next

### Phase 1: Connector Hardening

- finish AWS VPC Flow edge-case handling
- add Azure auth/config lifecycle
- verify checkpoint resume across restarts
- verify poll/backfill/status paths per connector

### Phase 2: Correlation and FP Reduction

- improve account anomaly joins
- improve network + endpoint overlap detection
- tune suppression and baselines
- validate manager/analyst report quality

### Phase 3: Self-Hosted Launch Pack

- Docker Compose launch profile
- .env example
- operator quickstart
- health/status dashboard
- pilot dataset + replay pack

## Launch Positioning

The honest launch position is:

> Janusec is a self-hosted AWS-first and Azure-minimum security sieve for network, endpoint, and IAM telemetry. It triages deterministically, enriches selectively, correlates across domains, and recommends gated follow-up evidence collection for analysts and threat hunters.

That is credible, sellable, and aligns with the current code direction.
