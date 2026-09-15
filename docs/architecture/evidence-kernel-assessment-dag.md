# Evidence Kernel and Assessment DAG

Status: accepted implementation direction (2026-08-18)

## Implementation checkpoint

The first dependency slice is implemented in this branch:

- tenant identifiers and authenticated/request ownership now fail closed at the
  middleware, upload, assessment persistence, runtime batch, graph cache, graph
  repository, replay, explanation, discovery, and cleanup boundaries;
- assessment upload, progress, evidence, cancel, and list operations require
  header/bearer authentication and exact tenant ownership; foreign identifiers
  return `404`, and the progress route no longer accepts API keys in its URL;
- new raw uploads are written once into contained tenant/assessment directories;
  duplicate sanitized filenames and unsafe storage identifiers are rejected,
  with case-distinct principals mapped to non-aliasing directory keys;
- JWT authentication now requires a tenant claim, except for the explicit
  tenantless `platform_admin` role; multipart tenant overrides require both an
  explicit non-production profile and `ALLOW_TENANT_OVERRIDE=1`;
- production graph sessions no longer invent missing batches, overlaps, edges,
  paths, hotspots, or findings, and report structured coverage gaps instead;
- EWMA now uses prior observations, records its history use, ignores unavailable
  batches rather than treating them as zero, and partitions production history by
  tenant;
- `src/core/evidence_contract/` provides immutable Evidence Contract v1 records,
  four timestamps, clock uncertainty, ACL/retention/classification/legal-hold
  labels, typed assertion classes, deterministic identifiers, stage manifests,
  pre-execution invocations, receipts, replay conflict detection, and DAG
  cycle/dependency validation.

This is a foundation, not a claim that the migration is complete. The existing
assessment worker has not yet been relabelled as a DAG. The next vertical slice
must wrap its real capture, parse, and normalize work with these contracts and
persist manifests/receipts durably before later stages are migrated.

One authentication migration also remains: the assessment progress flow no
longer places credentials in URLs, but legacy report/export helpers still build
query-authenticated URLs and the global compatibility middleware still accepts
them. Those links must move to session/OIDC or short-lived scoped download
tickets before query credential support is disabled globally.

## Decision

JanuSec will converge its upload, replay, CSV, streaming, and connector analysis paths on one tenant-scoped `AssessmentRun` directed acyclic graph (DAG).

The DAG is orchestration metadata, not the evidence graph shown to analysts:

- The **assessment DAG** describes which processing stages depend on which other stages.
- The **evidence graph** describes entities, events, assertions, and causal or candidate relationships found during an investigation.

Keeping those graphs separate prevents pipeline-control state from being confused with breach evidence.

## Why a DAG

A DAG is a directed graph with no dependency cycle. If stage B depends on stage A, the edge is `A -> B`. A cycle such as `A -> B -> A` is rejected before execution.

For JanuSec this replaces a fixed numbered checklist with explicit dependencies:

```text
capture -> parse -> normalize --+--> ip_enrichment -----+
                                +--> identity_resolution +--> causal_projection -> path_scoring
                                +--> binary_analysis ----+
causal_projection + evidence_quality -> evidence_pack -> verify -> narrate
```

This matters because it provides:

- Correct ordering: graph construction must precede graph path scoring.
- Safe parallelism: independent enrichment branches may run concurrently.
- Honest completion: a run completes only when required dependency branches and quality gates complete.
- Targeted retry: a failed enrichment can retry without rerunning immutable capture.
- Replay: stage inputs, versions, configuration hashes, and output receipts reconstruct the run.
- Idempotency: the same scoped input and stage version produce the same artifact identity.
- Degradation: optional stages can report `unavailable` without fabricating evidence.

The DAG must remain acyclic. Investigation iteration is represented as a new run/revision with explicit lineage, not by mutating an earlier stage output.

## Trust boundary

The DAG never owns or mutates raw evidence. Stages consume immutable evidence or artifact identifiers and emit new immutable artifacts and assertions.

Tenant and case scope are injected by the trusted runner. A stage or model may not select a different tenant through its payload.

Every stage receipt records at least:

- run, tenant, case, stage, and artifact identifiers;
- input artifact identifiers and hashes;
- plugin and schema version;
- configuration digest;
- start/end timestamps and terminal status;
- output hash, evidence references, quality metrics, and error/degradation reason.

## Reordered delivery sequence

The implementation order is based on dependency and risk, rather than product visibility:

1. **Safety envelope and regression baseline**
   - Enforce tenant ownership and safe tenant/path identifiers.
   - Disable synthetic evidence outside an explicit test/demo gate.
   - Capture golden breach, benign, missing-sensor, delayed-log, and cross-tenant cases.
2. **Evidence Contract v1**
   - Add deterministic evidence and assertion identifiers, raw hashes/locators, provenance, valid time, known time, ACL, and version fields.
3. **Assessment DAG foundation**
   - Validate dependencies/cycles, compute ready stages, persist manifests and receipts, and support replay/idempotency.
4. **One vertical production path**
   - Adapt the primary upload assessment worker to the DAG before migrating CSV, streaming, replay, or connectors.
5. **Causal/entity projections**
   - Separate observed causal edges from candidate entity matches and configured exposure.
6. **Hybrid retrieval and Evidence Packs**
   - Route exact, temporal SQL, graph, lexical, and dense retrieval; record support, contradiction, gaps, exclusions, lineage, and pack hash.
7. **Case frontend**
   - Render the server-owned case view model and synchronized claims, evidence, graph, timeline, and retrieval trace.
8. **Provider-neutral agent harness**
   - Derive model context from append-only session events and Evidence Pack references; keep verdict and authorization deterministic.
9. **Research extensions**
   - Evaluate temporal GNNs, additional graph stores, more connectors, and autonomous response only after the earlier gates pass.

## Initial stage ordering

The legacy 21 labels are retained only as a migration map:

1. Capture, parse, and normalize.
2. Run independent, versioned enrichments.
3. Generate entity candidates and resolve only sufficiently supported identities.
4. Construct time-valid observed, causal, and exposure projections.
5. Score paths and run anomaly/temporal analyses against those projections.
6. Construct claims, contradictions, coverage gaps, and multi-axis prioritization.
7. Compile and hash an Evidence Pack.
8. Verify the pack and claims.
9. Narrate verified results; the model cannot promote an inference to observation.

## Required acceptance gates

- No cross-tenant read, cache hit, graph traversal, or artifact reuse.
- No synthetic event, entity, edge, hotspot, or finding in the production profile.
- Replaying identical raw evidence under the same profile yields identical evidence, assertion, and artifact identifiers.
- Historical analysis uses event/valid time and knowledge time rather than current wall-clock age.
- Every report claim resolves to supporting evidence or is explicitly marked unsupported/inferred.
- Missing and contradictory evidence remain visible to the analyst.

## Non-goals for the foundation

- Replacing the current stack with microservices.
- Making a graph database the system of record.
- Allowing an LLM to schedule outside its scoped capability set.
- Treating stage count as a quality or completeness metric.
- Automatically executing containment actions without policy and human approval.
