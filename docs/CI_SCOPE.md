# Preview CI scope

The preview gate runs the explicit modules in `config/release_test_files.json`.
It covers the repaired tenant, verdict, evidence, history, connector and export
boundaries. It is not the entire repository suite.

`pytest-lite.yml` retains its automatic selected checks and weekly full-suite job;
the full job now actually has a schedule-only condition. Bandit, CodeQL, dependency
and container scans retain their existing automatic triggers.

Other historical workflows are retained as manual jobs with their steps intact.
They cover environment-specific experiments and integrations that have not been
certified for this preview. This limits automatic execution; it does not claim those
suites passed. Re-enable each automatic trigger after provisioning its dependencies
and recording a successful run. A green preview gate does not override a failed
security scan or weekly full-suite run.

Manual workflows in this revision:

- `acceptance.yml`
- `api-stage-harness.yml`
- `audit.yml`
- `auto_audit.yml`
- `benchmark-ci.yml`
- `ci-demo.yml`
- `ci-matrix.yml`
- `ci-poetry.yml`
- `ci-process-pool.yml`
- `ci-staging.yml`
- `ci-supervisor-full.yml`
- `ci-supervisor.yml`
- `ci-test.yml`
- `ci-tfidf.yml`
- `ci-validate.yml`
- `ci.yml`
- `clustering-quality-gate.yml`
- `coverage_matrix.yml`
- `crypto-tests.yml`
- `emission-coverage.yml`
- `evidence-ci.yml`
- `fast-tests.yml`
- `focused-tests.yml`
- `grounding-gate.yml`
- `helm-ci.yml`
- `integration-tests.yml`
- `k6-smoke.yml`
- `lite-tests.yml`
- `llm-eval.yml`
- `llm-mock-tests.yml`
- `llm-quality-nightly.yml`
- `llm-row-regression.yml`
- `migrations-and-db-tests.yml`
- `migrations.yml`
- `playwright.yml`
- `pr-artifacts.yml`
- `promtool.yml`
- `pytest-full.yml`
- `pytest.yml`
- `qualys-integration.yml`
- `redis-migration-and-tfidf.yml`
- `redis-tests.yml`
- `rule_quality.yml`
- `self_check.yml`
- `smoke.yml`
- `telemetry-smoke.yml`
- `terraform-plan.yml`
- `tfidf-seed.yml`
- `update_coverage_baseline.yml`
- `vault-integration.yml`
- `verify-audit.yml`
- `zap-baseline.yml`

## Security reporting limitation

Bandit and pip-audit are advisory finding reports. They now use supported JSON
output, preserve the actual findings, and fail if the scanner cannot produce a
valid report. A successful advisory job means the report was generated; it does
not mean the source or dependency set has no vulnerabilities. Review those reports
before any production deployment. The publication secret scan fails on unresolved
findings and the selected trust suite fails on errors, failures or skips.

The first real report (September 14) contained 4,108 Bandit findings, including
38 rated high: 37 weak-hash construction sites and one shell-based migration
runner. The migration runner has since been changed to an authenticated, scoped,
non-shell invocation with credential-safe arguments/output. The hash sites include
legacy protocol fingerprints and identifiers; they need compatibility-aware review,
not a blanket algorithm substitution or an assertion that all are exploitable.
The dependency audit on that run reported no advisories for its resolved set.
