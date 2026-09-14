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

The development preview is available for review in PR #1. Do not promote it to
main while security findings remain unresolved. The initial CodeQL alert gate
reported 315 new alerts (7 critical, 259 high, 49 medium), despite passing
functional checks. Alert counts are not confirmed exploit counts. Fix and verify
true positives; any false-positive resolution needs evidence for that data flow.
Do not suppress rules or narrow the scan simply to obtain a green check.

Corrections under verification restrict scanner and webhook selections to
operator-configured targets; real scans fail without demo fallback. HTML output
fails closed, raw HTML-to-PDF input loses active/resource-bearing markup, and
storage identifiers reject traversal and Windows aliases. Broad path handling,
logging of sensitive data and remaining report surfaces still need review.

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
