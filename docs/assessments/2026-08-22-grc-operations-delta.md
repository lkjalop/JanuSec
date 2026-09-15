# JanusSec GRC operations delta — 2026-08-22

## Demonstrated locally

- Persisted action transitions cover assign, approve, implement, request verification,
  independently verify, close, reject, and reopen. Invalid transitions and closure
  without verification evidence are rejected.
- Audit-bearing GRC mutations require a JWT identity and role scope. API keys remain
  usable for read-only case review but cannot become the accountable workflow actor.
- Read-only before/after verification adapters retain provider-native records for
  Entra/M365, AWS, GCP, Alibaba, EDR, firewall, and Veeam. Exact expected-state checks,
  native IDs, event times, clock uncertainty, and signed snapshot receipts are retained.
- Signed data-classification and regulatory-applicability snapshots gate the obligation
  engine. Missing truth produces `insufficient_information`; matching incident facts
  produce a review decision, never an automatic legal conclusion.
- Missing IAM, topology, CMDB, classification, and applicability truth now creates five
  assignable read-only collection tasks, each with an owner, approval boundary, safety
  warning, verification procedure, and required closure receipts.
- Outbound ServiceNow, Vanta, LogicGate, Protecht, and Ideagen dispatch is explicit,
  approval-gated, HTTPS-only, idempotency-checked before network dispatch, and recorded
  in an append-only receipt ledger. Tokens are not persisted in receipts.
- Alembic migration `0013_grc_dispatch_receipts` is the current head and adds PostgreSQL
  append-only mutation triggers plus tenant/case-scoped idempotency.

## Browser acceptance

The current Vesper assessment loads in the canonical Case Workspace. The action-plan
tab displays five of five blocked-information tasks. Each task explains the exact
collection action and closure evidence. An attempted assignment using the development
API key was rejected with `jwt_grc_actor_required`, proving the UI cannot silently use
an API key as a human sign-off identity. The page reported no new console errors after
authenticated reload.

## Accuracy evidence

The authoritative role-aware gate remains green:

- Vesper: must-detect 1.0, must-suppress 1.0, role attribution 1.0.
- Meridian: must-detect 1.0, must-separate 1.0, must-suppress 1.0, role attribution 1.0.
- Santos: must-suppress 1.0, with no false confirmed or false suspected case reported
  by the labelled gate.

The older structural `scripts/e2e_assess.py` gate is red and must not be hidden by
updating its baseline. Current deltas include extra actionable and isolated clusters,
oversized cluster capping, Meridian evidence retention 0.837, Santos retention 0.5675,
and three Santos actionable clusters without shared user/IP/host rollups. This may be
a stale baseline, a mismatch between structural and role-aware eligibility, or a real
partition/retention regression. It requires reconciliation before release.

## Fourth-corpus status

Alice was run blind through parse, normalization, entity resolution, and clustering:
241 rows, 21 actionable clusters, 8 isolated clusters, 100% structural retention, zero
oversized clusters, zero empty-entity clusters, and 9 deterministic validated-breach
labels. No sealed independent truth fixture exists, so false-breach, unsafe-action, or
false-compliance-conclusion rates cannot honestly be calculated yet. Do not tune against
Alice before an independent reviewer seals claim-, role-, separation-, suppression-, and
action-safety labels.

## External custody gate

Managed staging deployment was not attempted because this host has no configured staging
PostgreSQL URL, WORM bucket, AWS KMS key, or Azure Key Vault key; AWS CLI is absent and
Azure CLI is unauthenticated. A target account, explicit authorization, credentials, and
retention policy are required. Local success is not evidence of managed PostgreSQL,
Object Lock/WORM, backup/restore, or cloud-key behavior.

## Reordered next gates

1. Reconcile the red structural gate with the green role-aware gate. Explain every extra
   partition and retention loss; fix the evaluator or reconstruction, then freeze both.
2. Have an independent reviewer seal Alice truth before scoring it. Measure false
   confirmed, false suspected, unsafe recommendations, unsafe execution proposals, and
   false compliance conclusions without tuning on Alice.
3. Exercise a real JWT/role matrix in the browser: control owner implements, a distinct
   verifier verifies, and an approver dispatches. Preserve before/after and dispatch receipts.
4. Configure a named managed staging target; run migrations with restricted roles and test
   append-only rejection, backup/restore, WORM retention/legal hold, and asymmetric signing.
5. Connect explicitly authorized read-only collectors and sanitized provider exports.
6. Add approved external-system mapping/configuration for each outbound connector and run
   sandbox idempotency/retry/error-handling acceptance.
7. Only after these gates, benchmark model context sizes and research ablations.
