Test-mode helpers and admin endpoints

This project provides a few lightweight helpers and HTTP admin routes intended
for use in test/lite contexts only. They are guarded and should not be exposed
in production unless explicitly enabled.

Environment guard
- The endpoints and helpers check for `PLATFORM_LITE_INIT` environment variable
  or the presence of `PYTEST_CURRENT_TEST` in the environment to enable test
  behavior.

Runtime helpers (importable)
- `src.api.runtime_state.seed_asn_counts(pairs: list[tuple[str,int]])`
  - Seeds ASN frequency counts for deterministic ASN rarity behavior in tests.
  - Example: `seed_asn_counts([('AS1', 50), ('AS_RARE', 1)])`

- `src.api.runtime_state.seed_dns_nxdomain(host: str, nxd: int, total: int)`
  - Seeds NXDOMAIN/NOERROR counts for `dns_agg` to allow deterministic NXDOMAIN
    rate tests.

- `src.api.runtime_state.drain_event_queue_for_tests()`
  - Synchronous helper that drains the in-process EVENT_QUEUE and ensures
    hopgraph ingestion runs for enqueued events. This helper is hardened to
    work whether an asyncio loop is running or not.

- `src.api.runtime_state.reset_for_tests()`
  - Clears the `DECISION_CACHE` and other in-memory stores used in tests.

Test-only HTTP admin endpoints
- `POST /api/v1/test/reset_and_drain`
  - Clears `DECISION_CACHE` and drains the event queue synchronously. Returns
    `{'status':'ok','drained': <count>}` on success.

- `POST /api/v1/test/decision_cache_clear`
  - Clears the decision cache and returns `{'status':'ok'}`.

Notes and safety
- These endpoints and helpers are explicitly intended for CI/test usage. The
  code guards against accidental exposure by requiring `PLATFORM_LITE_INIT`
  or the pytest runtime environment. Do not remove these guards.

- If you need external test harnesses to run these actions over HTTP, call the
  POST endpoints above rather than importing runtime helpers.
