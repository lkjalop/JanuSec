API Security Regression Packs

This folder contains scaffolding to build auth-aware API regression tests.

Structure:
- `fixtures.py` - helper fixtures for auth tokens and test tenants
- `tests/` - add pytest files that exercise endpoints with tenant-scoped tokens

How to run:

```bash
pytest -q tests/api_regression
```

Add tests that set `X-API-Key` and any `Authorization` header for OAuth flows.
