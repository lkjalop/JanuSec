# Emission Coverage Gate

This document explains the emission-coverage CI gate used by this repository and how to run the related tests locally for debugging.

What it does
- The emission-coverage test compares the set of emitted factor records (recorded by the in-process emission tracker) to the canonical taxonomy of factors. It fails when the percentage of taxonomy factors that have at least one emitted record is below a threshold.

Environment variables
- `EMISSION_COVERAGE_THRESHOLD` — integer percent (0-100). The minimum percentage of taxonomy factors that must have at least one emission for the test to pass. In the provided CI workflow the default is 10.
- `EMISSION_COVERAGE_AUTOSEED` — when `1` the test will insert one seed emission per taxonomy factor into the in-memory emission tracker. This is intended for local debugging only. CI must set this to `0`.

Running locally (PowerShell)
- Example: seed emissions and run the gate at 10% threshold:
  - $env:EMISSION_COVERAGE_THRESHOLD = '10'; $env:EMISSION_COVERAGE_AUTOSEED = '1'; python -m pytest -q tests/test_emission_coverage.py

CI notes
- The workflow file is `.github/workflows/emission-coverage.yml`. It runs the emission coverage test with `EMISSION_COVERAGE_AUTOSEED=0` by default.
- If you need to relax the gate temporarily, change `EMISSION_COVERAGE_THRESHOLD` in the workflow or in CI job environment settings.

Recommendations
- Start with a low threshold (10-30%) while more detectors are wired. Increase the threshold over time as coverage improves.
- Avoid enabling `EMISSION_COVERAGE_AUTOSEED` in shared CI runs as it defeats the purpose of measuring real emissions.
