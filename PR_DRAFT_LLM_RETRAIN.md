# PR Draft: LLM Client, Cost Ledger, Circuit-Breaker, and Deep Analyze scaffolding

Summary
- Added centralized `LLMClient` enhancements:
  - Per-tenant budget tracking and soft-threshold enforcement
  - In-memory fallback CostLedger and integration with `src/core/metrics/cost_ledger`
  - Auto-trip circuit-breaker when tenant warnings exceed threshold
  - Mock-mode support and unit tests
- Added `set_budget`/`get_budget` to `src/core/metrics/cost_ledger` for explicit budget persistence
- Added unit tests:
  - `tests/test_llm_prompt.py`
  - `tests/test_llm_circuit_breaker.py`
  - `tests/test_llm_enforcement.py`
  - `tests/test_llm_trip_behavior.py`
- CI: Added `llm-mock-tests.yml` workflow to run LLM tests with `LLM_MOCK=1`, supports `requirements.txt` and `pyproject.toml`/wheel fallback.

Testing Notes
- Run locally in lite-mode:

```powershell
$env:PLATFORM_LITE_INIT='1'; python -m pytest -q tests/test_llm_prompt.py tests/test_llm_circuit_breaker.py tests/test_llm_enforcement.py tests/test_llm_trip_behavior.py
```

- CI will run the same tests with `LLM_MOCK=1`.

Review Notes
- Key files to review:
  - `src/integrations/llm_client.py`
  - `src/core/metrics/cost_ledger.py`
  - New tests in `tests/`
  - `.github/workflows/llm-mock-tests.yml`

Design Decisions
- Used a simple `set_budget`/`get_budget` API on `CostLedger` for clarity — preserves `add_cost` semantics for counters.
- Metrics integration uses `src/artifact/cost_tracker` as a lightweight in-repo emitter; can be swapped to Prometheus/StatsD.
- Circuit-breaker uses in-memory state and is intended for single-process mode; for multi-process deployments consider storing breaker state in Redis or DB.

Next Steps
- Harden CI further for matrix/platforms if desired
- Add Prometheus/StatsD hooks behind env toggles
- Implement Deep Analyze pipeline and integrate summarizer into reports

---

Please review and I can open the PR branch and push these changes.