# Replay Diff Design

## Motivation
Replay currently reprocesses custody events over a time window but provides no comparison to original classifications. Analysts need to understand what changed (factors added/removed, confidence delta, verdict shifts) after detector upgrades or configuration changes.

## Goals
- Provide a structured diff between original session/event classification and replay classification.
- Support batch replay of N events with summarized aggregate changes.
- Enable detector regression analysis (false positive reductions, new true positives) and version migration validation.
- Avoid heavy storage duplication; leverage existing custody + session persistence files.

## Non-Goals (Phase 1)
- Perfect forensic parity (e.g., raw PCAP or full artifact snapshots).
- Multi-tenant isolation (handled separately in multitenancy design).
- Real-time streaming backpressure handling for large replays.

## Core Concepts
1. Original Snapshot: Classification artifacts persisted at initial processing (session JSON, decision records, factor lists).
2. Replay Snapshot: Classification artifacts produced when reprocessing with new code/config.
3. Diff Record: Structured comparison capturing changes.

## Data Structures
```jsonc
// Event-level diff
{
  "event_id": "evt:123",
  "original": {"verdict": "OBSERVE", "confidence": 0.42, "factors": ["high_entropy"]},
  "replay":   {"verdict": "SUSPECT", "confidence": 0.78, "factors": ["high_entropy","asn_rare"]},
  "factor_added": ["asn_rare"],
  "factor_removed": [],
  "confidence_delta": 0.36,
  "verdict_changed": true,
  "detector_version_map": {"dns_exfil": "v2", "file_hash_rarity": "v3"},
  "timestamp": 1730851200
}

// Session-level diff (aggregated)
{
  "session_id": "session-1700000012345",
  "original": {"verdict": "OBSERVE", "confidence": 0.55, "factors": ["cross_mapping_correlation"]},
  "replay":   {"verdict": "SUSPECT", "confidence": 0.71, "factors": ["cross_mapping_correlation","dns_exfil","file_hash_rare"]},
  "factor_added": ["dns_exfil","file_hash_rare"],
  "factor_removed": [],
  "confidence_delta": 0.16,
  "verdict_changed": true,
  "changed_factors": {
     "dns_exfil": {"score_prev": null, "score_new": 0.65},
     "file_hash_rare": {"score_prev": null, "score_new": 0.7}
  },
  "detector_version_map": {"dns_exfil": "v2", "file_hash_rarity": "v3"},
  "timestamp": 1730851205
}
```

## API Surface (Phase 1)
1. `POST /api/v1/replay/diff` payload:
```json
{
  "from": 1730851200,
  "to": 1730851800,
  "limit": 2000,
  "include_sessions": true,
  "persist": true,
  "detector_versions": {"dns_exfil": "v2", "file_hash_rarity": "v3"}
}
```
Response:
```json
{
  "window": {"from": 1730851200, "to": 1730851800},
  "events": {"count": 1200, "diffs": [/* event diff records */]},
  "sessions": {"count": 12, "diffs": [/* session diff records */]},
  "summary": {
    "verdict_changed": 34,
    "avg_confidence_delta": 0.08,
    "factors_added_total": 57,
    "factors_removed_total": 3,
    "top_new_factors": [{"factor":"asn_rare","count":16}],
    "false_positive_suppressions": 5
  }
}
```

2. `GET /api/v1/replay/diff/{session_id}` – returns diff for a single session (if persisted).

## Persisted Artifacts
- Diff JSON stored under `data/replay_diffs/` named by start-end window hash or session id.
- Optional summary index file for quick dashboard retrieval.

## Algorithm Outline
1. Load original artifacts: sessions (session JSON), decisions/factors (custody lines), filter by window.
2. Reprocess target events through detectors & session builder (reuse existing build endpoint logic).
3. Capture replay classification outputs (verdict, confidence, factor set & scores).
4. Compute diffs:
   - Set operations on factor lists to derive added/removed.
   - Numeric delta on confidence.
   - Verdict comparison.
   - Per-factor score change (map by name + sha when available).
5. Aggregate summary statistics.
6. Persist diff files if requested.

## Edge Cases
- Missing original session file (mark `original_missing": true`).
- Factor suppression active during replay (record `suppressed_factors`).
- Detector removal (factor previously present, now absent – counts as removed).
- New detectors without version mapping (assign `"unknown"`).
- Replay limit truncation (set `truncated": true`).

## Performance Considerations
- Stream processing: iterate custody JSONL lines once; avoid full in-memory load for large windows.
- Optional `dry_run` flag to skip persistence and only return summary when volume high.
- Use batching for session rebuilds (group by session key prefix when present).

## Metrics Additions
- `replay_diff_events_total` (Counter)
- `replay_diff_verdict_changed_total` (Counter)
- `replay_diff_confidence_delta` (Histogram)
- `replay_diff_factor_added_total{factor}` (Counter)

## Phase 2 Enhancements
- Tenant-scoped replay diff.
- Drill-down UI with factor evolution timeline.
- Confidence modeling version diff (model output explanation vs previous).
- Automated regression classification (net improvement score).

## Security & Governance
- Require elevated scope (`replay:diff`) for diff APIs.
- Enforce per-key quotas (max windows/day, events per replay).
- Sanitize factor names and session ids before persistence.

## Open Questions
- Should factor score changes influence a stability metric?
- Include raw event payload diffs? (likely optional privacy toggle)
- Need checksum of original vs replay configuration for audit trail?

## Implementation Steps
1. Create diff builder module `src/core/replay/diff_builder.py` with functions:
   - `collect_original(window)`
   - `replay_events(events)`
   - `diff_event(original, replay)`
   - `diff_session(original, replay)`
2. Implement new endpoints.
3. Add metrics.
4. Add tests (small window, known factor additions).
5. Document usage in existing README.

## Success Criteria
- Diff endpoint returns deterministic output in test mode.
- Added/removed factors accurately reflect replay changes.
- Confidence delta calculations correct to within float tolerance.
- Metrics increment as expected.
- Persisted diff artifacts readable and include summary block.
