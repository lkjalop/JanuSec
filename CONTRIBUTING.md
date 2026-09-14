# Contributing

Contributions should be limited to sanitized rule templates, documentation, and reproducible demos. Do not commit any proprietary detection logic or customer data.

See `examples/detection-rules/README.md` for format.
# Contributing Guidelines (Focused on Reliability & Correlation Additions)

Thank you for contributing to JanuSec. This guide highlights the reliability / test strategy and recent correlation + HopGraph instrumentation so you can avoid common pitfalls.

## Test Strategy

We use a two-pass sequential strategy to surface order-dependent issues and keep async plugin overhead isolated:

1. Fast Sync Pass: `python scripts/run_tests_sequential.py` (first pass) runs each test file with plugin autoload disabled (`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`). This catches import errors, state bleed, and most logic failures quickly.
2. Targeted Async Pass: The same script (second pass) detects files containing `@pytest.mark.asyncio` or `async def test_` and re-runs only those with the `pytest_asyncio` plugin explicitly loaded. Alternatively, run the dedicated async-only script:

```powershell
python scripts/run_tests_async_only.py
```

Environment variables:
- `TEST_PER_FILE_TIMEOUT_SEC` – Per-file timeout (default 40 for sequential, 60 for async-only script).
- `TEST_TWO_PASS=0` – Disable second (async) pass if you only want a fast smoke.

## Correlation Modules
- Temporal sequence correlator (`src/correlation/temporal.py`): emits `corr:multi_stage_lateral_beacon` when pattern (rare lineage → lsass access → periodic beacon) occurs within window & outside cooldown.
- Co-occurrence correlator (`src/correlation/cooccurrence.py`): computes pointwise mutual information (PMI) over factor co-occurrence; emits `corr:pair_high_pmi` when count & PMI thresholds are met.

Key env vars (see README table for full list):
- `CORR_TEMPORAL_WINDOW_SEC`, `CORR_TEMPORAL_MAX_EVENTS`, `CORR_TEMPORAL_COOLDOWN_SEC`
- `COOCC_ENABLED`, `COOCC_MIN_COUNT`, `COOCC_PMI_THRESHOLD`, `COOCC_MAX_PAIRS`, `COOCC_COOLDOWN_SEC`

## HopGraph Watermarks & Metrics
- Soft / hard edge watermarks (`HOPGRAPH_SOFT_EDGE_WM`, `HOPGRAPH_HARD_EDGE_WM`). Hard breach triggers proportional trimming (keep newest 75%).
- Metrics: `hopgraph_total_edges`, `hopgraph_soft_edge_watermark`, `hopgraph_hard_edge_watermark`, plus existing `hopgraph_edges_total`, prune counters, explain cache hit/miss metrics.

## Adding New Tests
- Prefer small deterministic fixtures; avoid real network / Redis dependencies—use fakes or monkeypatch.
- Keep runtime < 2s per file; if longer, add internal timeouts or rate-limit loops.
- If adding async tests, ensure they can run under `pytest-asyncio`; keep sleeps minimal (<0.1s) or monkeypatch intervals.

## Factor Naming Governance
- Use clear prefixes: `net:`, `endpoint:`, `ssl:`, `corr:` etc. Correlation factors should always start with `corr:`.
- If creating new adjustable factors, consider adding observe-mode gating via `adjust_delta`.

## Performance Considerations
- When adding correlation logic, bound memory: use size/time-limited structures (deques, soft caps).
- Expose new counters/gauges with best-effort try/except so metrics library absence doesn’t break tests.

## Pull Request Checklist
- [ ] Added/updated tests (positive + negative + boundary).
- [ ] Ran `scripts/run_tests_sequential.py` locally (all green).
- [ ] Metrics names reviewed for cardinality explosion risk.
- [ ] README / docs updated if new env vars or user-visible behaviors.
- [ ] No long blocking sleeps in tests (use intervals/env overrides).

## Questions
Open a discussion or file an issue with context (what you changed, expected vs actual behavior, reproduction steps).

Happy hunting! 🛡️
