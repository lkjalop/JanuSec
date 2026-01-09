# Changelog

## 2026-01-09
- Fix: correct indentation bug in LLM row processing in `src/api/deep_analyze_endpoints.py` which could cause import-time failures.
2025-11-06 - Fix: webhook dispatch SSRF guard - honor test env overrides and prevent route shadowing (integrations_endpoints.py)

## Unreleased

- Fix: endpoint malware analyze handler — read JSON from request and avoid FastAPI dependency body parsing bug; explicit auth call to `auth_dependency` (tests: `tests/test_endpoint_malware.py` now pass).
