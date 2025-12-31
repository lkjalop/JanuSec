## Summary

This pull request adds a public-facing README, sanitized documentation, example detection rule templates, a synthetic event generator, and demo matcher scripts for reproducible demos.

## What I changed
- Added README.md updates with ASCII architecture and userflows
- Added docs/ with sanitized architecture and deployment guides
- Added examples/ with detection-rule templates and correlation samples
- Added tools/data-ingestion-simulator/ with `generate_events.py` and `demo_matcher.py`
- Added whitepapers/ and marketing drafts

## Why
To provide a public, sanitized showcase of JanuSec architecture, example artifacts, and a reproducible demo harness for mentors and prospective users.

## Checklist
- [ ] Documentation reviewed for sensitive content
- [ ] Tests / CI passing for demo scripts
- [ ] PR description updated with notes for reviewers

## How to test locally
```bash
python tools/data-ingestion-simulator/generate_events.py --count 20 | python tools/data-ingestion-simulator/demo_matcher.py
```

Please review the docs and examples for any missing redactions before merging.
# HopGraph Scoring, Persistence, and Factor Expansion Improvements

## Summary
- Adds mapping semantics and domain diversity weighting to composite scoring (env-tunable, defaults now nonzero)
- Implements adaptive EWMA alpha (variance-driven) for session correlation smoothing
- Integrates mapping semantics-derived factors into session build and confidence
- Improves session store concurrency (lock file for JSON, retry/backoff for SQLite)
- Adds integration test for session store concurrency (multi-threaded)
- Adds metrics export for scoring influences (logging)
- Expands runbook with env var, API, and output examples
- Updates documentation (AGENTS.md, runbook)

## Details
- New weights: `SCORING_MAPPING_WEIGHT`, `SCORING_DIVERSITY_WEIGHT`, or `SCORING_WEIGHTS_JSON` (JSON blob)
- Adaptive EWMA: `ADAPTIVE_EWMA=1` enables volatility-driven alpha, with tunable min/max/base/scale
- Session build factors now include mapping semantics richness/bonus/support
- Confidence formula now includes mapping semantics bonus
- Concurrency: lock file for JSON, retry/backoff for SQLite
- Integration test: `tests/test_session_store_concurrency.py`
- Logging: composite, mapping, diversity, ewma influences
- Runbook: `docs/graph_session_runbook.md` with env/API/output examples

## Testing
- All graph session and new concurrency tests pass
- Manual env var tuning verified influence in logs and API output

## Checklist
- [x] All tests pass
- [x] Docs updated
- [x] New features env-tunable and backward compatible

---
