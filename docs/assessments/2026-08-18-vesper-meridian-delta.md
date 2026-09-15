# Vesper and Meridian acceptance delta — 2026-08-18

## Scope and method

- Reran the complete deterministic Vesper and Meridian ground-truth suites after stripping upload-controlled answer-key fields and notes.
- Exercised the canonical case workspace at desktop and mobile sizes with Playwright, including upload, async assessment progress, and every workspace tab.
- Compared JanusSec output with an independent GPT-5.6 Sol reconstruction of the raw records.
- Ran immutable local-model comparisons with Qwen3.8:27b and Qwen3:14b.
- Inspected graph projection cost, Evidence Pack 2.1 selection, contradiction checking, model evaluation, and the maker/checker/critic loop.

## Acceptance result

The deterministic truth gate passes both corpora. Vesper processes 98,750 rows; Meridian processes 24,438 rows. Meridian's required James, Wei, and public-S3 crawler investigations are detected and separated at the gate. The gate is now stronger than the old “some breach detected” check because it includes must-detect, must-separate, must-suppress, and role assertions.

This does not mean the analyst presentation is complete. The gate and the UI are different acceptance surfaces, and the remaining discrepancies below are material.

## Delivered in this run

- Campaign presentation no longer promotes every typed campaign to `VALIDATED_BREACH`; source verdicts survive into threat cases.
- Kerberoast target accounts no longer become standalone breach actors. Rebuilding the persisted Vesper presentation yields one Martin case with `svc_backup` and `svc_sql` as explicit target roles and supporting clusters.
- Evidence Pack compilation now receives normalized, content-addressed local evidence rather than only ingestion manifest records.
- The process-lineage corrective policy detects the intended Meridian clock/order conflict: encoded PowerShell at 09:06:30 precedes its named `cmd.exe` parent at 09:06:55. PID reuse and unrelated same-name processes are bounded to avoid broad false contradiction matches.
- Graph projection writes are batched and repeated semantic edges are aggregated; disconnected event nodes were removed while evidence IDs retain lineage.
- The browser harness now adopts the assessment ID produced by upload and avoids clicking hidden tabs when an assessment has not completed.
- Mobile evidence rendering is bounded to 40 visible rows, although true API pagination/virtualization remains required.

## Vesper: JanusSec versus GPT-5.6 Sol

The gate correctly identifies Martin Chen, malicious OAuth entry, six accumulated phases, and 7,152,369,907 bytes of exfiltration. The corrected presentation keeps roasted service accounts as targets.

GPT-5.6 Sol produced the more defensible reconstruction: malicious OAuth consent on 12 April, Romanian refresh-token redemption, X509 credential persistence, AD recon, AS-REP roasting, WMI/PowerShell movement, long-lived RC4 ticket evidence, and staged SharePoint exfiltration. It also distinguished observation from inference.

The Qwen3.8:27b run was valid JSON but missed the OAuth entry and specific persistence mechanisms, did not quantify the 7.15 GB exfiltration, and proposed uncited actions. Its recorded evaluator result was attribution quality 0.75, evidence recall 0.0245, unsupported-claim rate 0.25, and 20 analyst nodes to inspect. The reported 0.97 confidence is not calibrated to those omissions.

## Meridian: JanusSec versus GPT-5.6 Sol

The evidence supports at least three investigations:

1. James: supplier-file/macro entry, encoded PowerShell and credential harvesting, C2, stolen-key SSH, bastion/Kubernetes movement, secret enumeration, eBPF activity, and later token/C2 exfiltration.
2. Wei/NovaBridge: sensitive SharePoint access, external forwarding, attachments, and Alibaba-origin AWS credential use. This is suspected insider or credential abuse; the telemetry cannot justify geopolitical attribution.
3. Public-S3 crawler: enumeration and about 2.9 MB of object downloads, including a misplaced internal brief. This must not merge with the NovaBridge service actor.

The presentation still contaminates Wei with `bastion_rdp_lateral` and merges the NovaBridge service actor with the public crawler in one confirmed card. The Lisa lookalike-domain message remains a separate unconfirmed attempt. Alibaba-origin `PutObject` means data was written into S3; it is not outbound exfiltration. Later `GetObject` events are the stronger disclosure evidence.

Qwen3.8:27b crashed inside the local Ollama/GGML runtime. That failure is not yet persisted as an immutable failed model run. Qwen3:14b completed but repeated only the Wei summary, omitted James and the crawler, and produced uncited decisions. Its recorded evaluator result was attribution quality 0.25, evidence recall 0.00736, and unsupported-claim rate 0.75.

## Browser and usability assessment

The static v2 fixture and live Vesper/Meridian workspaces render on desktop and mobile, and the tabs are wired. Projection receipts and current/stale state reach the view model. The interface is not yet an effective five-page GRC product:

- the top-level summary is assessment-wide rather than case-partitioned;
- milestones are generic and omit the meaningful attack sequence;
- immediate decisions are often empty;
- role and authorization paths are not prominent;
- “1% completeness” reflects a 500-row preview cap, not evidentiary completeness;
- the mobile tab rail clips and sticky panes can visually collide;
- 40-row CSS hiding reduces page length but is not server pagination.

Screenshots and clickthrough traces are under `dump/reports/case-v2-acceptance/`.

## Graph and retrieval assessment

The optimized Vesper graph projection contains roughly 2,209 nodes and 67,780 persisted typed edges. A direct build of 73,163 unique semantic edges took about 11.7 seconds, but the full worker still peaked around 2.49 GB because it retains the corpus, projection, and narration inputs together. Chunked or incremental immutable projection is therefore a production prerequisite.

Evidence Pack 2.1 now has real local evidence and finds support, excluded candidates, lineage, hashes, and the Meridian temporal contradiction. Remaining defects are:

- retrieval is not first partitioned by authoritative case membership;
- exact identifier matching over-selects and the returned evidence cap is not a defensible ranking;
- dense retrieval is not configured;
- TemporalRAG prior-case memory is in-memory and disappears on restart;
- source sensor names do not yet share one canonical taxonomy;
- graph traversal evidence IDs and pack ranking need end-to-end reconciliation;
- CMDB mappings and signed mapping receipts are absent.

## What spatiotemporal and HippoRAG do — and do not do

The failure was not simply “missing HippoGraph.” It was primarily weak semantic direction, identity roles, case boundaries, topology constraints, and presentation contracts. Spatiotemporal reasoning helps by combining event/ingest/known/valid time, clock uncertainty, asset and network topology, authorization paths, and action direction. It can reject impossible orderings and qualify a relationship as observed, configured, candidate, contradicted, or unknown.

HippoRAG/PPR is associative retrieval over a knowledge graph. It can surface distant related context, but it does not establish causality or evidence truth. Applied before case boundaries are reliable, hub nodes such as shared IPs, users, service accounts, and common infrastructure can increase over-stitching. It should remain a scored, shadow retrieval projection whose candidates require local corroboration.

## Reordered roadmap

### P0 — trustworthy case production

1. Make case partitions first-class API resources and compile one Evidence Pack and one model run per immutable partition. Fix the remaining Meridian crawler/service merge and Wei/RDP contamination.
2. Complete role-aware, provider-directional normalization and conformance fixtures. Never promote fixture labels or candidate matches to evidence.
3. Decouple deterministic assessment completion from optional model narration. Add model deadlines, circuit breaking, and immutable failed-run records.
4. Rank case-local evidence, align canonical sensor taxonomy, and reconcile graph edge evidence IDs with pack selection.
5. Deploy migrations to staging PostgreSQL; test append-only triggers, backup, WORM retention, and legal hold. Replace full in-memory projection with chunked or incremental immutable manifests when latency/memory budgets are exceeded.

### P1 — defensible reconstruction and GRC action

6. Generate milestones from typed phase evidence, including roles, authorization paths, direction, success/denial, topology, and clock uncertainty.
7. Add source-specific contradiction policies, clock-skew calibration, persistent TemporalRAG prior-case retrieval, and a real dense-document adapter.
8. Add signed CMDB/service-catalog mappings before emitting business-impact claims.
9. Add analyst sign-off, control owner, due date, compensating control, containment state, decision rationale, and verification evidence to the GRC Action Pack.
10. Attach labelled truth sets to every comparison and expose attribution quality, separation/suppression, evidence recall, unsupported claims, contradictions, calibration, nodes-to-inspect, and time-to-defensible-conclusion.
11. Replace the mobile evidence-table workaround with server pagination or virtualization and simplify the executive brief.

### P2 — controlled research experiments

Baseline exact + lexical + typed traversal first, then ablate TemporalRAG and dense retrieval. Only after P0/P1 gates hold should HippoRAG/PPR, Graphiti-style session memory, and temporal-GNN scoring run in shadow mode. No research projection may mutate the ledger, case boundary, verdict, or containment authority.

## Product conclusion

JanusSec is not currently a better reasoner than a frontier model. Its defensible role is the governed evidence and operations layer around replaceable reasoners: custody, normalization, case boundaries, replay, retrieval receipts, calibration, analyst decisions, and safe actions. If it remains “upload logs and receive prose,” a frontier model wins. If it becomes a reproducible breach-to-GRC decision system, frontier models become replaceable investigators inside the product.
