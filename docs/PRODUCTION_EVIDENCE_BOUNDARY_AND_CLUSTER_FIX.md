# JanuSec Production Evidence Boundary and Cluster Surfacing Fix

## Purpose

This is the implementation handoff for making JanuSec an evidence-bound breach assessment platform.

The immediate goal is not a broad multi-agent rewrite. The immediate goal is to prevent poisoned or non-evidence inputs from influencing production verdicts, then improve cluster ranking/naming so the breach page surfaces concrete evidence-based threat cases instead of generic pivot buckets.

This document is written for a coding agent to execute.

## Production Principle

JanuSec must be an evidence-bound reasoner, not an opinionated one.

A `confirmed` or `suspicious` finding must be grounded in uploaded telemetry rows. Business context, platform priors, LLM prose, and prior assessment history may enrich or downgrade a finding only within explicit policy rules. They must not create facts or verdicts by themselves.

## Current Problem Summary

The Santos browser ingestion path now proves the enrichment workbook is quarantined:

- `janusec_enrichment_context_v1.xlsx` contributes `0` evidence rows.
- Browser upload succeeds through `/static/breach.html`.
- The breach page renders clusters.

But the top cards are still generic pivot clusters such as:

- `Shared pivot user:rachel.nakamura@santosfreight.com.au`
- `Shared pivot user:hector.alvarez@santosfreight.com.au`

This is not acceptable for production. Broad user/host pivots should be supporting correlation, not the lead threat cases. A small high-quality LSASS or DNS chain should outrank a large generic pivot if it has concrete evidence.

## Evidence Lanes

Every input and derived object must carry a lane and provenance.

### `telemetry_evidence`

Uploaded logs/events. This is the only lane that can create `confirmed_threat` or `suspicious_unconfirmed` findings.

Allowed:

- create row refs
- create entities
- create timestamps/time windows
- create technique/tool/command observations
- support confirmed/suspicious findings

### `business_context`

CMDB, HR, approved travel, asset inventory, approved engagement windows, vendor register.

Allowed:

- enrich severity/business impact
- downgrade a finding when attributes match
- add context notes

Not allowed:

- create a breach finding by itself
- create row refs
- create entities not observed in telemetry
- silently suppress findings without provenance

### `evaluation_answer_key`

Ground truth sheets, scoring packs, Santos enrichment workbook, benchmark answer keys.

Allowed:

- offline scoring/evaluation only

Not allowed:

- production analysis input
- production finding creation
- production verdict influence
- UI narrative input

### `platform_prior`

Rules, ATT&CK mappings, reputation heuristics, known TTP dictionaries.

Allowed:

- `score_delta`
- `weight_multiplier`
- `context_note`
- `candidate_mapping`

Not allowed:

- sole source of `entity`
- sole source of `technique_id`
- sole source of `row_ref`
- sole source of `timestamp`
- sole source of a confirmed/suspicious claim

Example: a JA3 prior may say "this resembles a C2 fingerprint" only if uploaded telemetry has a JA3 row ref. It may increase the score of that evidence-bound finding. It cannot create a C2 finding on its own.

### `llm_narrative`

Generated prose.

Allowed:

- terminal UI/report rendering only

Not allowed:

- input to detectors
- input to rankers
- input to RAG/memory for future production assessments
- evidence source
- provenance source

Flow allowed:

```text
structured finding -> LLM narrative -> UI
```

Flow forbidden:

```text
LLM narrative -> RAG/cache/history -> future analysis
```

### `cache_or_history`

Prior assessments, saved reports, memory/state.

Allowed:

- display historical context when explicitly requested
- show "similar prior case" references

Not allowed:

- silently influence current verdict
- provide current row refs
- create findings
- leak entities/narratives between assessments

## Classification Buckets

Use these classification buckets for analysis clusters and threat cases:

- `confirmed_threat`
- `suspicious_unconfirmed`
- `authorized_or_benign`
- `context_only`
- `unclassified_telemetry`
- `suppressed_low_signal`

Do not use "background noise" for rows that were not explicitly classified benign.

## Minimum Threshold Policy

These thresholds should be implemented as named constants so they can be tuned later.

### `confirmed_threat`

Requires:

- `row_refs >= 2`
- `source_files >= 2` where available, or a documented exception for single-source high-fidelity telemetry
- at least one concrete `entity`
- concrete `time_window`
- at least one `technique`, `tool`, or `command`
- `kill_chain_length >= 2` where available
- `confidence >= 0.85`
- all claims have `sources` pointing to `telemetry_evidence`

### `suspicious_unconfirmed`

Requires:

- `row_refs >= 1`
- at least one concrete `entity`
- concrete `time_window` if available
- at least one of `technique`, `tool`, `command`, `destination`, or `behavior`
- `confidence >= 0.60`
- at least one named evidence gap
- all claims have telemetry provenance

### `authorized_or_benign`

Requires:

- telemetry-bound suspicious activity exists
- context downgrade has provenance
- downgrade matches at least two attributes from:
  - `entity`
  - `time_window`
  - `source_infra`
  - `destination_infra`
  - `tool`
  - `account`
  - `approved_scope`

Do not downgrade based on a single weak match such as "there was a pentest this month."

### `context_only`

Context records with no telemetry evidence.

Must not appear as breach/suspicious top cards.

### `unclassified_telemetry`

Rows retained/analyzed but not converted into a finding.

Must be numerically honest and inspectable.

### `suppressed_low_signal`

Evidence exists but does not meet suspicious/confirmed thresholds.

Must be inspectable in inventory but not lead top cards.

## Existing File Anchors

Use these current anchors. Line numbers are from the current workspace at the time this document was written.

### Ingestion Lane Classification

File: `src/core/ingest/input_classifier.py`

- Lines 13-22: `TELEMETRY_SHEETS`
- Lines 24-32: `EVALUATION_ANSWER_KEY_SHEETS`
- Lines 34-40: `BUSINESS_CONTEXT_SHEETS`
- Lines 47-49: `is_non_evidence_sheet`
- Lines 52-98: `classify_xlsx_sheets`
- Lines 101-117: `classify_xlsx_path`

Needed changes:

- Expand this module from XLSX-only classification into a general evidence lane policy module.
- Add constants for all lanes:
  - `TELEMETRY_EVIDENCE`
  - `BUSINESS_CONTEXT`
  - `EVALUATION_ANSWER_KEY`
  - `PLATFORM_PRIOR`
  - `LLM_NARRATIVE`
  - `CACHE_OR_HISTORY`
- Add helpers:
  - `is_evidence_allowed(lane: str) -> bool`
  - `can_create_finding(lane: str) -> bool`
  - `can_downgrade(lane: str) -> bool`
  - `require_telemetry_provenance(finding: dict) -> list[str]`
  - `validate_context_downgrade(finding: dict, context: dict) -> bool`

### XLSX Parsing

File: `src/core/ingest/file_parser.py`

- Lines 189 onward: `_parse_xlsx`
- Lines 204-205: current classifier call

Needed changes:

- Ensure non-evidence workbooks return no telemetry rows.
- For allowed telemetry rows, attach row-level provenance:
  - `provenance.lane = "telemetry_evidence"`
  - `provenance.file`
  - `provenance.sheet`
  - `provenance.row_index`
- For context/evaluation files, return quarantine metadata through upload API if needed, but do not yield telemetry rows.

### Workbook Sheet Upload API

File: `src/api/upload_endpoints.py`

- Lines 1651 onward: `upload_workbook_sheets`
- Lines 1697-1705: current classifier call and provenance handling

Needed changes:

- Return lane classification to the caller.
- Reject or quarantine `evaluation_answer_key`.
- Mark `business_context` as non-evidence.
- Do not let workbook sheets from non-evidence lanes flow into production assessment evidence.

### Legacy Deep Analysis Hydration

File: `src/api/deep_analyze_endpoints.py`

- Lines 3013-3015: `_build_enrichment_guided_cases` currently returns `[]`
- Lines 3569-3608: `_hydrate_assessment_semantics`
- Lines 3574-3578: non-evidence sheet filtering
- Lines 3581-3602: cluster creation and assignment

Needed changes:

- Keep `_build_enrichment_guided_cases` inert in production.
- Add a guard/test proving it cannot return production cases unless an explicit evaluation/scoring path is used.
- In `_hydrate_assessment_semantics`, validate that rows used for clusters are `telemetry_evidence`.
- Add output provenance for `assessment["correlation_clusters"]`.
- Do not call LLM or narrative fields as input to `_build_correlation_clusters`.

### Async Assessment Worker

File: `src/core/ingest/assessment_worker.py`

- Lines 221-230: `source_counts` and `evidence_store`
- Lines 234-255: current SQL pivot cluster generation
- Lines 284-292: `build_threat_cases` layering
- Lines 299-318: LLM narration and tier-1 prefill scheduling

Needed changes:

- Add assessment-level `evidence_policy` block:
  - `policy_version`
  - `allowed_finding_lanes`
  - `quarantined_inputs`
  - `context_inputs`
  - `telemetry_inputs`
- Attach source/lane provenance in `evidence_store`.
- Do not set `assessment["correlation_clusters"]` to broad pivot clusters for UI ranking without a material finding layer.
- Keep `raw_correlation_clusters`, but introduce or populate material `analysis_clusters`.
- Ensure LLM narration is terminal and cannot mutate evidence fields used by ranking/classification.

### Threat Case Builder

File: `src/core/ingest/threat_case_builder.py`

- Lines 92-106: `build_threat_cases`
- Lines 109-151: `_build_analysis_clusters`
- Lines 154-289: `_build_presentation_cases`
- Lines 133-148: current simple classification
- Lines 246-280: current unclassified telemetry case

Needed changes:

- This is the main implementation target.
- Add a `CandidateFinding`-style internal object or dict with:
  - `finding_id`
  - `domain`
  - `pattern`
  - `classification`
  - `entities`
  - `time_window`
  - `techniques`
  - `tools`
  - `commands`
  - `destinations`
  - `source_files`
  - `row_refs`
  - `evidence_gaps`
  - `confidence`
  - `confidence_calibration`
  - `sources`
  - `supporting_cluster_ids`
- Build concrete material findings before presentation cases.
- Demote broad pivots like `Shared pivot user:*` unless they contain a concrete pattern.
- Rank concrete evidence findings above broad pivots.
- Add deterministic names for known patterns:
  - `Rclone Backblaze Exfiltration`
  - `LSASS Credential Theft`
  - `Snowflake UNLOAD Data Movement`
  - `K8s Privileged Container Escape`
  - `Low-Reputation DNS Beaconing`
- Preserve all raw clusters in `raw_correlation_clusters`.
- Keep unclassified telemetry, but do not use `NO_VALIDATED_BREACH` in a way that implies rows are benign.

### Breach API Endpoints

File: `src/api/breach_endpoints.py`

Important existing cluster reads:

- Line 393: `clusters = assessment.get('correlation_clusters') or []`
- Line 1176: `clusters = assessment.get('correlation_clusters') or []`
- Line 1564: `clusters = assessment.get('correlation_clusters') or []`
- Line 1598: `clusters = assessment.get('correlation_clusters') or []`
- Lines 1746, 1849, 1879, 1908, 1934: more cluster reads

Needed changes:

- Prefer `analysis_clusters` for assessment-level breach UI and summaries.
- Keep `raw_correlation_clusters` available for audit/inventory.
- Ensure executive summary does not use LLM narrative as evidence.
- Ensure final verdict is derived from classified evidence-bound findings, not prose.

### Breach UI

File: `frontend/static/js/breach.js`

- Lines 109-118: `loadAssessment`
- Line 114: `state.clusters = data.correlation_clusters || []`
- Lines 796-835: `renderHome`
- Lines 837-880: `_hydrateTopThreatCases`
- Line 1016: unclassified telemetry wording
- Lines 1522-1588: `_renderCard`
- Lines 1590-1622: `_renderCardLoading`

Needed changes:

- In `loadAssessment`, prefer:

```js
state.clusters = data.analysis_clusters || data.correlation_clusters || [];
state.rawClusters = data.raw_correlation_clusters || [];
state.threatCases = data.threat_cases || [];
```

- Top cards should use material `threat_cases` or ranked `analysis_clusters`, not raw broad pivots.
- Render classification buckets explicitly:
  - confirmed
  - suspicious
  - authorized/benign
  - suppressed low signal
  - unclassified telemetry
- Keep unclassified telemetry wording:
  - "unclassified telemetry, not confirmed benign"
- Do not reintroduce "background noise."
- Add provenance badges or drilldown:
  - lane
  - source file
  - evidence row refs
  - context downgrade reason, if any

### Cluster Detail UI

File: `frontend/static/js/breach_cluster_tab.js`

- Line 268: `data-testid="bct-evidence-narrative"`
- Line 344: main wrapper

Needed changes:

- Show structured provenance.
- Distinguish evidence rows from context notes.
- Do not present context-only material as proof.

## Required Tests First

Add or update tests before implementation.

### Existing Test Anchors

File: `tests/test_analysis_production_boundaries.py`

- Lines 13-23: enrichment workbook quarantine test
- Lines 26-51: production import boundary test
- Lines 54-84: scenario token scanner
- Lines 87-111: raw/analysis/threat-case inventory preservation

File: `tests/test_santos_enrichment_guided_cases.py`

- Lines 9-23: Santos enrichment workbook is not production evidence

File: `tests/playwright/breach_santos_ingestion.spec.js`

- Lines 299-318: current top cluster narrative test area

### Add These Unit Tests

Add to `tests/test_analysis_production_boundaries.py` or a new `tests/test_evidence_policy.py`.

1. `test_confirmed_or_suspicious_requires_telemetry_row_refs`

Given findings from `business_context`, `platform_prior`, `llm_narrative`, or `cache_or_history`, assert they cannot be classified as `confirmed_threat` or `suspicious_unconfirmed` without telemetry row refs.

2. `test_platform_prior_cannot_create_fact_fields`

Given a platform prior with technique/entity but no telemetry source, assert validation strips or rejects:

- `entity`
- `technique_id`
- `row_ref`
- `timestamp`

3. `test_llm_narrative_is_terminal`

Given an assessment with `llm_narrative`, assert cluster building/ranking does not read prose fields as evidence input.

4. `test_context_downgrade_requires_two_attribute_matches`

One matching attribute should fail downgrade. Two matching attributes should pass.

5. `test_evaluation_answer_key_cannot_create_findings`

Given Santos enrichment workbook or rows marked `evaluation_answer_key`, assert no finding/threat case is created.

6. `test_santos_material_findings_are_named_and_ranked`

Using representative rows, assert top material findings include at least:

- `LSASS Credential Theft`
- `Snowflake UNLOAD Data Movement`
- `K8s Privileged Container Escape`
- `Rclone Backblaze Exfiltration`

DNS beaconing should be included if the current uploaded telemetry contains enough evidence.

7. `test_broad_pivot_is_demoted_below_specific_threat_pattern`

Given:

- a 200-row shared-user pivot
- a 2-row LSASS chain

Assert LSASS ranks above broad pivot.

### Add/Update Playwright Acceptance

Update `tests/playwright/breach_santos_ingestion.spec.js`.

Add assertions after fetching assessment JSON:

- `xlsx_enrichment_rows === 0`
- `analysis_clusters.length >= 5`
- top cards are not all `Shared pivot ...`
- rendered page contains at least three material threat case names or subtitles
- rendered page does not contain:
  - `janusec_enrichment_context`
  - `HR_Directory`
  - `Threat_Intel_IOCs`
  - `Crown_Jewels_Register`
  - `background noise`

## Implementation Sequence

Do not do this as a one-shot rewrite. Execute in this order.

### Step 1: Evidence Policy Module

Create or extend:

- `src/core/ingest/input_classifier.py`

Add lane constants and validation helpers.

Acceptance:

- unit tests for lane permissions pass
- Santos workbook still quarantines

### Step 2: Provenance Tagging

Modify:

- `src/core/ingest/file_parser.py`
- `src/core/ingest/assessment_worker.py`
- `src/api/upload_endpoints.py`

Every row/finding should have structured provenance.

Recommended shape:

```python
"sources": [
    {
        "lane": "telemetry_evidence",
        "file": "janusec_network_v1.csv",
        "row_refs": [106, 110],
        "sheet": None,
    }
]
```

Acceptance:

- every suspicious/confirmed analysis cluster has at least one telemetry source
- non-evidence inputs are listed under `quarantined_inputs` or `context_inputs`, not source counts

### Step 3: Policy Enforcement

Modify:

- `src/core/ingest/threat_case_builder.py`
- `src/api/deep_analyze_endpoints.py`
- `src/api/breach_endpoints.py`

Enforce:

- no confirmed/suspicious classification without telemetry row refs
- platform priors cannot create fact fields
- context downgrade requires two attribute matches
- LLM narrative is terminal

Acceptance:

- all policy tests pass

### Step 4: Material Finding Builder

Modify:

- `src/core/ingest/threat_case_builder.py`

Add deterministic material pattern extraction before ranking. Start with simple pattern detectors from evidence rows and cluster text:

- LSASS credential theft:
  - terms: `lsass`, `comsvcs`, `procdump`, `mimikatz`, `credential dumping`
- Rclone/cloud exfiltration:
  - terms: `rclone`, `backblaze`, `mega`, `b2`, `external storage`, `data exfil`
- Snowflake UNLOAD:
  - terms: `snowflake`, `unload`, `copy into`, `stage`, `query_history`
- K8s escape:
  - terms: `k8s`, `kubernetes`, `privileged`, `container`, `falco`, `serviceaccount`, `pod`
- DNS beaconing:
  - terms: `dns`, `beacon`, `nxdomain`, `low reputation`, `periodic`

Acceptance:

- specific material findings rank above generic pivots
- broad pivots still exist in raw inventory

### Step 5: UI Surfacing

Modify:

- `frontend/static/js/breach.js`
- `frontend/static/js/breach_cluster_tab.js`

Acceptance:

- top three cards are concrete evidence-backed cases when available
- generic pivots move to supporting/inventory sections
- unclassified telemetry remains honest
- page still answers CEO question:
  - confirmed breach?
  - suspicious but unconfirmed?
  - ruled out?
  - unclassified?

### Step 6: Live Browser Verification

Run live Docker/local flow after tests:

1. Start app with deterministic LLM for acceptance:

```powershell
$env:API_KEYS_JSON='[{"key":"devkey123","scopes":["*"]}]'
$env:API_KEY='devkey123'
$env:STRICT_API_KEY_ENFORCEMENT='1'
$env:ENABLE_JOB_WORKER='1'
$env:DEBUG_DIAGNOSTICS='1'
$env:LLM_PROVIDER='mock'
$env:OLLAMA_HOST=''
docker compose build app
docker compose run -d --name janusec-santos-pw --user root --entrypoint python -p 18080:8080 -e API_KEY -e API_KEYS_JSON -e STRICT_API_KEY_ENFORCEMENT -e ENABLE_JOB_WORKER -e DEBUG_DIAGNOSTICS -e LLM_PROVIDER -e OLLAMA_HOST app -m uvicorn src.api.app:app --host 0.0.0.0 --port 8080
```

2. Upload Santos files through browser path:

- `dump/test files/janusec_endpoint_k8s_v1.ndjson`
- `dump/test files/janusec_network_v1.csv`
- `dump/test files/janusec_cloud_identity_v1.json`
- `dump/test files/janusec_enrichment_context_v1.xlsx`

3. Capture screenshots:

- before/after home page
- expanded top card
- evidence tab if changed

4. Verify:

- enrichment workbook rows are zero
- no hardcoded Santos tokens leak into Alice runs
- top cards are concrete findings
- debug endpoint shows zero backend errors

Cleanup:

```powershell
docker rm -f janusec-santos-pw
```

Do not stop `janusec-db-1` or `janusec-redis-1` unless explicitly needed.

## Acceptance Criteria

The work is complete only when all are true:

1. Santos enrichment workbook is quarantined and contributes zero evidence rows.
2. No production path imports from `tests`, `fixtures`, `dump`, or `evaluation`.
3. No confirmed/suspicious finding exists without telemetry row refs.
4. Platform prior cannot be the sole source of entity, technique, row ref, or timestamp.
5. LLM narrative is terminal and cannot feed analysis/ranking.
6. Context downgrade requires at least two matched attributes and provenance.
7. `raw_correlation_clusters` are preserved.
8. `analysis_clusters` are policy-classified.
9. `threat_cases` are presentation views over analysis clusters, not replacements.
10. Top breach cards surface concrete evidence-backed material findings when present.
11. Generic broad pivots are still inspectable but do not outrank specific threat patterns.
12. UI uses "unclassified telemetry, not confirmed benign" instead of "background noise."
13. Live browser Santos screenshot shows improved top cards.
14. Alice-after-Santos isolation test shows zero Santos bleed.

## Expected Before/After Delta

Before:

- enrichment workbook risked poisoning analysis
- top cards were generic user pivots
- unclassified rows could be framed as background noise
- CEO-level answer was unclear
- suspicious small chains could be hidden behind broad pivots

After:

- non-evidence is quarantined or context-only
- all findings carry provenance
- confirmed/suspicious means telemetry-backed
- top cards show material attack patterns
- weak/suppressed/unclassified clusters remain inspectable
- verdict answers "confirmed breach or not?" with evidence and gaps

## Notes for Claude Code

Do not start with a multi-agent rewrite. Do not add parallel LLM reasoning yet.

Build the evidence boundary first. Then fix deterministic finding/ranking. Then run browser verification and screenshots.

If a test cannot be written to fail before the fix, stop and re-scope that item.

