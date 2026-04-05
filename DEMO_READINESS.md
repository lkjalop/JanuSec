Demo readiness checklist and timeline for CEO demo

Objective

Prepare a stable, demonstrable build that exercises pattern detection, correlation, the audit runner, and basic metrics reporting.

Minimum Acceptance Criteria

- CI pipeline run completes (unit tests + smoke import) without hard failures.
- `scripts/audit_runner.py --strict` runs and produces rubric JSON with metrics history when `--metrics-history-dir` is supplied.
- Regex engine instrumented and does not raise syntax/indentation errors; metrics counters exposed when `prometheus_client` is installed.
- Threat model Controls Matrix appended and visible in `THREAT_MODELING.md`.
- SBOM and secret-scan artifacts produced by supply-chain job in CI.

3-Day Execution Plan

Day 0 (Prep):
- Ensure local environment has Python 3.11 and dependencies from `requirements.txt` installed.
- Run `pytest -q` and fix any import-time errors.
- Install `prometheus_client` in a virtualenv for metrics verification.

Day 1 (Stabilize):
- Fix the remaining instrumentation issues in `src/modules/regex_engine.py` (done).
- Run a local smoke execution of the regex engine against crafted test events.
- Validate that `DEMO_READINESS.md` checklist items are green.

Day 2 (Polish & Demo Run):
- Execute `scripts/audit_runner.py --strict` and collect rubric snapshot.
- Start a lightweight Prometheus instance and scrape metrics from a small demo runner (optional).
- Record a 5-10 minute demo video showing detection, threat model summary, and metrics dashboard.

Contingencies

- If prometheus_client is unavailable, the system will run with metrics no-ops (see `src/core/metrics.py`).
- If SBOM generation fails due to environment constraints, provide `requirements.txt` and `pip freeze` outputs as a fallback.

Contact

Reach out to the engineering lead for any last-minute emergency fixes. Mark issues as P0 in the tracker for immediate attention.

## How To Validate (Demo Guards)

- Egress Safety: set a webhook URL to `http://127.0.0.1:9/...` and call `/api/v1/webhooks/dispatch` → blocked with `ssrf_blocked`.
- Content-Type: POST plain text to `/api/v1/integrations/slack/config` → 400 `bad_json` (or 415 by proxy).
- HMAC/Replay: call `/api/v1/webhooks/*` without `X-Timestamp` and `X-Signature` → 400/401; send same tuple twice → 409 replay.
- Upload Limits: oversize CSV/JSON/ZIP to `/api/v1/upload/files` → `analysis.truncated == true` or member `skipped` markers.

Grafana: “Egress Safety” row shows `webhook_ssrf_blocks_total` and breakdown by reason.
