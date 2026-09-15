# Isolated authentication and recovery verification — 2026-09-14

This extends the evidence review preview with a local, single-writer HTTPS
deployment using production authentication. It does not certify a customer
deployment, live collection, external model quality or corrective-action efficacy.
The canonical LIVE console is unchanged by this work.

## Repairs demonstrated

- Production startup rejects permissive test flags, conflicting environment
  profiles, weak/unbound credentials and disabled API authentication. Production
  requests cannot use pytest authentication bypasses or development fallback keys.
- The canonical server's replacement lifespan now starts essential ingest recovery.
  Previously, an interrupted upload could remain running until another upload
  started the worker.
- Restored captures resolve inside the current tenant-owned directory, with all
  registered hashes and sizes checked. Interrupted derived rows are rebuilt without
  duplicating physical rows. Missing captures fail the whole job.
- Equal-score evidence now has deterministic ordering. An earlier restore check
  found identical IDs and contents in a different order; that failed check was
  retained, then the ordering and content comparison were corrected.
- Upload copying enforces a byte cap in bounded chunks. Failure to register raw
  metadata prevents queueing. Legacy and V2 checkpoints use separate state paths.
- Complete offline backups encrypt the state with AES-256-GCM and an independent
  recovery key. Restoration validates authentication and member hashes before
  extraction into a new directory. An incomplete restore cannot start serving.

## Observed local results

The selected regression suite passed all **620 tests** with no failures or skips.
This is the explicit release selection, not every test in the repository.
Existing dependency/lifespan deprecation warnings remain. Publication path and
workflow checks passed; Gitleaks found no leaks in the staged publication tree.

The final controlled crash interrupted Vesper after 98,750 derived rows had been
written. A 48-file encrypted backup (85,875,400 bytes) restored into a new directory.
Automatic recovery completed with exactly **98,750 physical rows and 98,750 distinct
row indices**. Four raw captures resolved under the restored root. An encrypted
synthetic canary, both checkpoint formats and the evidence ledger survived.

The previous completed case retained all 445 evidence rows, the same case hashes
and an exact historical receipt. The stable evidence content digest was
`3ec4f9189296454fc1f7ff563bcbe51911bf8db80c82956677c97a2ffe427568`.
The Vesper assertions passed: one detection, seven suppressions and three entity
roles. These are synthetic acceptance assertions, not field accuracy estimates.

TLS certificate validation passed in the API verifier. Missing, wrong and public
development keys returned 401; the configured key returned 200. Expired JWTs
returned 401, foreign evidence 404 and tenant-header override 403. Anonymous admin
and integration requests were rejected.

Real Chromium exercised five LIVE tabs, evidence drilldown, authenticated export,
mobile layout and reload against the restored production-auth server. No routes
were mocked; no JavaScript or HTTP errors were observed. Chromium allowed the
generated localhost certificate; the API verifier separately validated that
certificate. These checks do not establish public TLS or SSO readiness.

A bounded sample of 40 reads from four clients had zero errors, p50 0.820 seconds,
p95 0.990 seconds and maximum 1.016 seconds. Earlier complete Vesper runs measured
approximately 2.6–2.7 GiB peak process-tree RSS. The final crash sample stopped early
and is not a capacity measurement. A 1 GiB limit is unsupported; 4 GiB is a starting
qualification allocation, not an SLO. No multi-hour load test was performed.

## Remaining release gates

1. **Retained public key copy:** the scrubbed feature branch returns 404, but the
   old commit still returns 200 for the key path. Three known local key files were
   checked and do not match the exposed fingerprint. The Support draft is prepared
   but not submitted; no removal confirmation exists. Audit other deployments for
   reuse. Rotation does not itself remove the retained copy.
2. **Customer deployment:** validate access roles/SSO, managed TLS and rotation,
   an enforced memory/disk/ingress boundary, sustained load, monitoring ownership,
   and restoration from an off-host archive with separately escrowed recovery key.
3. **One approved live source:** collect actual provider records, reconcile counts
   and receipts, restart from a real checkpoint and compare resulting evidence.
   The synthetic canary/checkpoint drill does not satisfy this gate.
4. **Corrective-action proof:** record authenticated review, an approved provider
   change and a later observation that demonstrates its effect. Keep unsupported
   control failure and breach claims explicitly unproven.

The product remains an evidence-backed security investigation and review tool.
These changes make its existing workflow recoverable and constrain unsafe
conclusions; they do not introduce a telemetry-routing product or Cribl integration.
See [operator commands and boundaries](../../ISOLATED_PILOT_OPERATIONS.md).
