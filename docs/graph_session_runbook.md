Graph Session Runbook

Environment variables affecting graph session build and scoring

- `ADAPTIVE_EWMA` (0/1): enable adaptive EWMA alpha derivation when `ewma` is requested but `ewma_alpha` omitted. Default `0`.
- `ADAPTIVE_EWMA_BASE_ALPHA`: base alpha used when adaptive enabled (default `0.6`).
- `ADAPTIVE_EWMA_MIN_ALPHA`: minimum allowed alpha (default `0.3`).
- `ADAPTIVE_EWMA_MAX_ALPHA`: maximum allowed alpha (default `0.85`).
- `ADAPTIVE_EWMA_VOL_SCALE`: volatility scale when deriving alpha (default `0.4`).
- `SCORING_DIVERSITY_WEIGHT`: numeric weight applied to `domain_diversity` component (default `0.0`).
- `SCORING_MAPPING_WEIGHT`: numeric weight applied to `mapping_semantics` component (default `0.0`).
- `SCORING_WEIGHTS_JSON`: JSON blob to atomically override multiple weights, e.g. `{"path":0.25,"diversity":0.07}`.


Quick examples (PowerShell):

```
$env:SCORING_MAPPING_WEIGHT='0.07'
$env:SCORING_DIVERSITY_WEIGHT='0.05'
$env:ADAPTIVE_EWMA='1'
python -m pytest -q tests/test_graph_sessions.py
```

Sample API call (using httpie):

```
http POST http://localhost:8080/api/v1/graph/session/build \
		session_ids:='["batch-abc123","batch-def456"]' \
		correlate:=true ewma:=true mapping:='{"user":"user","host":"host","sha256":"file_hash"}'
```

Sample response excerpt:

```
{
	"session_id": "sess-...",
	"summary": {
		"confidence": 0.81,
		"verdict": "escalate",
		"factors": [
			{"name": "multi_source_correlation"},
			{"name": "entity_diversity_high"},
			{"factor": "mapping_semantics_rich", "score": 0.6},
			{"factor": "mapping_semantics_bonus", "score": 0.1}
		],
		"correlation": { ... },
		"correlation_smoothed": { ... },
		"ewma_alpha": 0.54,
		"mapping_stats": {"user": "user", "host": "host", "sha256": "file_hash"},
		...
	}
}
```

Notes
- Mapping semantics influence is computed from canonical field coverage across provided session batches and contributes small bonus factors (e.g. `mapping_semantics_rich`).
- Adaptive EWMA derives `ewma_alpha` from variance/mean of pairwise overlaps when the caller omits an explicit `ewma_alpha` value.
- Default weights remain conservative (0.0 for new components) so enabling these env vars is required to change scoring behavior.

Recommended tuning
- Start with `SCORING_MAPPING_WEIGHT=0.05` and `SCORING_DIVERSITY_WEIGHT=0.03`, observe composite changes via API responses, then incrementally adjust.
