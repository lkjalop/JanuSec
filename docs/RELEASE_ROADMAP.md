# Release roadmap

## Preview release gates

1. Local exposed file-store encryption has been rotated; the published token
   payload was traced to dummy test values. Audit other deployments for key reuse
   and rotate/revoke any real credentials found there.
2. Remove private/runtime material from publishable source and reachable history.
   Address retained GitHub commit views through the sensitive-data removal process.
3. Build a clean candidate, run trust-boundary tests and real-backend browser
   journeys, and publish the exact commit with its scoped results.
4. Keep README claims aligned with those results and preserve explicit limitations.

## Current publication hold

The development preview is available for review in PR #1. Main remains unchanged.
Promotion requires resolved security gates and completion of the retained-copy
removal process. A real connector pilot is still an operational release gate.

The September 14 security continuation repaired storage containment, tenant
mismatch handling, label ownership, credential-bearing audit records, integration
encryption, callback authentication, response errors and unsafe text parsing.
Connector transports disable redirects/proxies and reject unsafe schemes. Optional
models require immutable revisions and safetensors; local pickle artifacts require
an operator-owned exact-hash approval. See the README for changed configuration.

CodeQL scans the full configured Python scope. False positives are reviewed per
alert, with a reason; rules were not disabled to clear the gate. Bandit now blocks
high-severity findings while retaining all lower-severity findings in its artifact.
Remaining binding, detector-string, parameterized-SQL and approved-deserialization
warnings need their documented context; a passing scanner job is not a security
certification. Exact-commit results are available on PR #1.

Real scanner targets require `JANUSEC_APPROVED_SCANNER_TARGETS`, a JSON array of
exact approved CLI targets. Real notifications require
`JANUSEC_APPROVED_WEBHOOK_URLS`, a JSON array of exact HTTPS destinations, also
checked against the outbound address policy. These settings are operator-owned;
request callers cannot extend them. Webhook redirects and environment proxies
are disabled. Use domains controlled by the approved provider and enforce network
egress controls in deployment.

GitHub retained old-commit views still require the sensitive-data removal process.
Rewriting branch history does not remove those cached views or others' clones.

## Product work after the preview

The next customer proof of concept is deliberately narrow: one tenant, approved
read-only collection, a case with complete source references, and a reviewed
next action. The full Meridian/Santos/Vesper replay and browser verification are
documented in [the corpus report](verification/2026-09-14-corpus-pilot/README.md).
Use [the demo guide](DEMO_GUIDE.md) for its observable acceptance criteria.

The selected corpus cases currently show no qualified action-plan items or
control impacts. Wiring one evidence-cited proposal into authenticated review
and later provider verification is the next product step. Broad model, agent and
catalog expansion should follow that customer workflow.

Before handling real customer data, validate a deployment profile with measured
memory/latency, tenant-bound production authentication, managed secrets and
durable storage. The existing 1 GiB Helm limit is below the observed peak of a
local corpus run. Exercise backup restoration across evidence, history, ingest
state and checkpoints; completed-case restart tests do not prove that recovery.

- Recover legacy ownership only from authoritative jobs or re-ingest; never guess.
- Extend history capture and versioned model inputs. Earlier uncaptured derivations
  cannot be presented as reconstructed historical truth.
- Load versioned authoritative catalogs beyond NIST and review mapping meaning,
  customer applicability, exceptions and expected operating conditions.
- Prove a real connector: collection receipt, normalized evidence, checkpoint/restart
  recovery, case, candidate control concern, authenticated review, corrective action,
  and subsequent provider evidence. Fixtures are not a live pilot.
- Evaluate models on representative positive, negative and incomplete cases.
- Connect reviewed agent baselines to authenticated live telemetry and measure
  cold-start, authorized changes, poisoning resistance and false positives.
- Validate customer-specific OSCAL profiles, imported assessment plans and buyer
  acceptance. Schema validity alone does not establish audit suitability.

The focus is traceable incident evidence and reviewable control assessments.
Expansion follows evidence quality and one demonstrated customer workflow.
