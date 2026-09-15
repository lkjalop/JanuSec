# Spatiotemporal Corrective Assessment Architecture

Status: implemented vertical slice, 2026-08-18

## Decision

JanusSec treats spatiotemporal reasoning as an evidence contract, not a new truth
engine. Every relevant record preserves event/observed/known/valid time, clock
uncertainty, tenant and topology. Graph queries declare a purpose and receive only
the edge families needed for it.

Case truth is partitioned before narrative generation. Shared IP, CIDR, hostname,
device, operation or TLS fingerprint is candidate/topology evidence and cannot, by
itself, union named principals or campaigns. Legacy weak unions are opt-in research
flags only.

## Engine roles

- ChronoGraph: persistent tenant-scoped counters, rates and baselines; not causality.
- HopGraph: an implementation behind the typed graph interface; not its own ontology.
- TemporalRAG: a prior-case/bitemporal adapter inside the retrieval router.
- CorrectiveRAG: the Evidence Pack verifier after retrieval.
- HippoGraph: reuse the ShopSquire ideas—typed contribution, bounded graph views,
  contradiction/supersession and trust projection—without a runtime dependency.
- Graphiti-style memory: model/analyst session memory only.
- Temporal GNNs: shadow scoring only until attribution and calibration gates pass.

`spatiotemporal` has two unrelated uses in the surrounding ecosystem.  In this
architecture it means event/observed/known/valid time plus network, identity and
service topology and clock uncertainty.  Cordis uses the same word for reversible
software effects across time and reactive dependency composition across space.  The
DeepSeek Harness pattern is useful for plugins and replay, but Cordis is not a cyber
event-correlation algorithm.

HippoRAG/HippoGraph-style retrieval is also not the evidence graph.  It is an
associative shadow index over eligible typed nodes.  PPR/spreading activation may
propose overlooked neighbours; the Evidence Pack must still retain the typed path,
source evidence and temporal cutoff before any neighbour can support a claim.

## Projection freshness

PostgreSQL stores append-only typed node records, edge records and graph-view
receipts.  A view is stale, and must be rebuilt into a new projection, when:

- the eligible evidence-ledger head advances;
- the normalizer or mapping version changes;
- a required sensor's last-success watermark exceeds its source-specific SLA; or
- its CMDB/topology mapping validity interval expires.

Historical evidence is not stale merely because it is old.  Old projections and
receipts remain addressable so a report or model run can be reproduced exactly.

## Retrieval order

1. Canonical exact-identifier equality.
2. Tenant/case and bitemporal eligibility.
3. Bounded typed traversal that promotes the visited evidence records.
4. Lexical retrieval.
5. Optional provider-neutral dense retrieval over the eligible corpus.
6. Corrective verification of contradictions, causal clock order, candidate edges,
   missing sensors and alternative hypotheses.

The output is a content-addressed Evidence Pack v2.1. Dense or model providers may rank
or propose; they cannot create evidentiary records or turn candidate matches into
causal facts.

## Accuracy loop

The provider-neutral loop is maker -> checker -> critic. It appends every pack bind,
claim, verification, counter-hypothesis and completion receipt to the hash-chained
session log. It stops when the deterministic verifier accepts, when the evidence basis
does not change, or when the iteration budget is reached. Model confidence is not a
stop condition and does not change evidence or containment authority.

## Acceptance truth

The Vesper and Meridian fixtures now test cases and roles, not cluster counts:

- Vesper: Martin's entry point and chain; Priya/Anna/Sarah and benign service activity
  suppression; `svc_sql` and `svc_backup` are targets in the Martin case.
- Meridian: James, Wei and the anonymous public-S3 crawler are detected and separate;
  actor/victim roles are asserted; vendor email sender `info` is suppressed.

This is an attribution-quality gate. A result is not green merely because at least one
breach was detected.

## Delivery state

Delivered in the current vertical slice:

1. Active Alembic migrations `0009` and `0010`, append-only typed graph repository,
   AssessmentRun projection writes, content receipts, case/report freshness checks,
   and asynchronous rebuild scheduling.
2. One typed graph-session API boundary. Legacy edges survive only in a labelled
   presentation adapter; evidence-free causal edges are rejected.
3. Provider-aware semantic adapters for Azure, GCP, Alibaba, email, firewall,
   Suricata, Sysmon, eBPF, Nutanix, VMware and HPE, plus provider-neutral
   `cloud_object_collection`.
4. Evidence Pack v2.1 with separate case evidence and retrieved context, projection
   and ledger bindings, TemporalRAG adapters, contradiction policies, clock-skew
   calibration, alternative-hypothesis traces and excluded PPR candidates.
5. CMDB-receipt enforcement for business-service claims and immutable maker/checker/
   critic evaluation receipts in model comparison runs.

Still deployment or evaluation work, not a completed product claim:

1. Run `alembic upgrade head` against each configured PostgreSQL deployment and
   validate WORM/retention operations; local verification used a disposable database.
2. Add real CMDB/service-catalog connectors and source-specific production fixture
   packs beyond the current contract tests.
3. Supply labelled evaluation fixtures to calculate must-detect/separate/suppress
   within every model run; these metrics are intentionally unavailable on unlabeled
   customer cases.
4. Keep HippoGraph/PPR, Graphiti memory and temporal GNNs in shadow mode until the
   P0/P1 gates hold on representative production-like telemetry.

For live sources, configure optional per-sensor expiry with
`GRAPH_SENSOR_MAX_AGE_SECONDS_JSON`, for example
`{"sysmon":900,"cloudtrail":3600}`. Static/replayed evidence does not become stale
merely because time passed; staleness is tied to a declared required-sensor SLA.
