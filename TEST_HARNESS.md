Test Harness Notes
==================

This document explains the lightweight test harness conventions used by the project
to make unit tests deterministic and fast in CI.

Key points
- `PLATFORM_LITE_INIT=1`: when set, the application performs a lightweight initialization that avoids importing heavy optional dependencies and avoids starting long-running background tasks. CI uses this for the selected "lite" test suite.
- `tests/conftest.py`: provides small stubs for optional heavy dependencies (e.g. `psycopg2`, `boto3`, `google` SDKs) so pytest collection doesn't fail in environments where those drivers are not installed.

Why this exists
- Some modules import optional drivers (Postgres, cloud SDKs, etc.) at import time for convenience. During test collection this can cause `ModuleNotFoundError` and break the whole test run. The conftest stubs avoid that while keeping tests focused and deterministic.

How to run the lite tests locally
---------------------------------
Run the same command used in CI:

```powershell
$env:PLATFORM_LITE_INIT='1'
python -m pytest -q tests/test_webhook_guard.py tests/test_zeek_adapter.py tests/test_dread_scorer.py tests/test_intel_sync.py tests/test_bgp_network_wiring.py tests/test_ebpf_smoke.py tests/test_identity_snapshot.py tests/test_bgp_metadata_edges.py
```

Notes for contributors
- If a test needs real DB/cloud behavior, add a focused fixture in the test to monkeypatch the stub or install the real dependency in a dedicated environment.
- Keep `tests/conftest.py` small and explicit; avoid stubbing behavior that masks real regressions.

CI Workflows
------------
- The project exposes two GitHub Actions workflows:
	- `pytest-lite.yml` — runs the selected lite test suite on push/PR and schedules a weekly lite run.
	- `pytest-full.yml` — runs the full test matrix weekly/nightly and can be triggered manually via `workflow_dispatch`.

Badges
------
- Lite suite: `https://github.com/lkjalop/JanuSec/actions/workflows/pytest-lite.yml/badge.svg`
- Full suite: `https://github.com/lkjalop/JanuSec/actions/workflows/pytest-full.yml/badge.svg`
