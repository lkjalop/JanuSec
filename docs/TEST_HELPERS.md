# Test helpers

This repository exposes small runtime helpers to make tests deterministic and avoid cross-test state pollution.

reset_rate_limit_for_tests()
- Location: `src/api/app.py`
- Purpose: clear in-memory rate limiter windows and counters, and re-evaluate environment-driven rate limit configuration.
- Behavior notes:
  - Clears `_RATE_LIMIT_STORAGE` and tenant storages.
  - Re-reads `RATE_LIMIT_MAX_REQUESTS` and `RATE_LIMIT_WINDOW_SECONDS` from env.
  - Preserves an explicit module-level `_RATE_LIMIT_ENABLED` value if tests have monkeypatched it to `True` or `False`.
  - Honors `RATE_LIMIT_FORCE_ENABLE=1` to force the module-level `_RATE_LIMIT_ENABLED` to `True`.

Usage guidance
- Tests that need the rate limiter enabled should either:
  - Monkeypatch the module-level `_RATE_LIMIT_ENABLED` to `True` before calling `reset_rate_limit_for_tests()`; or
  - Set `RATE_LIMIT_FORCE_ENABLE=1` in the environment *before* importing `src.api.app`.

- After calling `reset_rate_limit_for_tests()` tests can pre-fill `_RATE_LIMIT_STORAGE[ip]` to create deterministic saturation scenarios.

Regression tests
- There are unit tests under `tests/test_reset_rate_limit_helper.py` that assert the helper preserves explicit True/False and respects `RATE_LIMIT_FORCE_ENABLE`.
