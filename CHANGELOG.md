2025-11-06 - Fix: webhook dispatch SSRF guard - honor test env overrides and prevent route shadowing (integrations_endpoints.py)

## Unreleased

- Fix: endpoint malware analyze handler — read JSON from request and avoid FastAPI dependency body parsing bug; explicit auth call to `auth_dependency` (tests: `tests/test_endpoint_malware.py` now pass).
