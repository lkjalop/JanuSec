# Graph Session Explain Endpoint

Endpoint: `GET /api/v1/graph/session/{id}/explain`

Returns an explainable narrative and structured scoring components for a previously built multi-source correlation session (created via `POST /api/v1/graph/session/build`).

## Response Fields
- `session_id`: ID of the session.
- `confidence`: Final confidence score (0..1).
- `verdict`: `escalate | watch | benign` heuristic.
- `key_factors`: Ordered distinct factors excluding `batch_missing` noise.
- `domains_present`: Detected domain keywords in batch ids.
- `domain_diversity_score`: Normalized domain diversity.
- `mapping_semantics_score`: Aggregate canonical field richness score.
- `volatility`: Variance/mean ratio of overlap counts (proxy for path volatility).
- `confidence_breakdown`: Component dictionary:
  - `base`: Base diversity-derived confidence.
  - `chain_bonus`: Multi-factor chain bonus (correlation + diversity / missing batches synergy).
  - `temporal_bonus`: Bonus when temporal pattern chains detected.
  - `mapping_bonus`: Mapping semantics factor aggregation bonus (pre-weight application).
  - `co_occurrence_adjustment`: Net adjustment from factor pair PMI / suppression templates.
  - `diversity_weight`: Weighted domain diversity contribution (env configured).
  - `mapping_weight`: Weighted mapping semantics contribution (env configured).
  - `final`: Final capped confidence.
- `overlap_hotspots`: Top batch-pair overlaps with field counts.
- `narrative`: Human-readable summary synthesizing fields above.

## Building a Session
Use `POST /api/v1/graph/session/build` with payload:
```json
{
  "session_ids": ["batch-abc123", "batch-def456"],
  "correlate": true,
  "ewma": true,
  "mapping": {"user":"user","host":"host"}
}
```
Response contains `session_id`. Then call:
```
GET /api/v1/graph/session/{session_id}/explain
```

## Frontend Integration (LIVE Console)
The LIVE console (`frontend/static/janusec-platform-complete-LIVE.html`) includes a new panel "Multi-Source Session Explain" in the right investigation sidebar. It attempts to auto-load the newest session id stored in `localStorage.lastTabularSessions` after upload flows. Manual explain is triggered with the Explain button which calls:
```js
fetch('/api/v1/graph/session/'+encodeURIComponent(sessionId)+'/explain', { headers: authHeaders() })
```
Then it populates:
- Confidence & verdict line.
- Narrative block.
- Hotspots pills (`a:b (fields)`).
- Breakdown pills (each component k=v plus final).

Helper: global `window.fetchSessionExplain(sessionId)` for other modules.

## Notes
- If no explicit `sessionId` provided in UI input, auto picks the last uploaded session (if any).
- Confidence weights can be tuned via env `SCORING_DIVERSITY_WEIGHT`, `SCORING_MAPPING_WEIGHT` or composite `SCORING_WEIGHTS_JSON`.
- Adaptive EWMA alpha labels not exposed here; view `/api/v1/graph/session/{id}` for raw smoothing matrices.
- Hotspots limited to top 10 pairs; breakdown limited to primary components.

## Error Handling
- 404 `not_found` if session missing (expired or never built).
- 401/403 propagated from auth middleware on strict mode.

## Test Guidance
A targeted test should:
1. Build a session using deterministic fixture batch ids (e.g. `batch-overlap-1`,`batch-overlap-2`).
2. Call explain endpoint.
3. Assert presence of `confidence_breakdown.final`, `narrative` non-empty, and at least one hotspot when overlap >0.
4. Validate factor filtering excludes `batch_missing` from `key_factors`.

---
Last updated: 2025-11-07
