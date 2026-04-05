Adaptive Backfill (Auto Deep Analyze)

This document describes the adaptive backfill feature for running the 21-step Deep Analyze pipeline across CSV assessments.

Env variables (defaults):
- BACKFILL_BATCH_SIZE (50)
- BACKFILL_WINDOW_SECONDS (30)
- BACKFILL_MAX_RUNTIME_SECONDS (2700)
- BACKFILL_MAX_RETRIES (3)
- BACKFILL_BACKOFF_BASE (2)
- API_BASE_URL (required for HTTP fallback when pipeline not importable)
- SESSION_PERSIST_DIR (default: <repo>/data/sessions)

Endpoints:
- POST /api/v1/csv/deep_analyze/auto_backfill
  Payload: { assessment_id, target_coverage=1.0, window_seconds, batch_size }
  Returns: { assessment_id, status: scheduled }

- GET /api/v1/csv/deep_analyze/auto_backfill/{assessment_id}/status
  Returns job state including processed, total, coverage, failed_rows.

Behavior:
- Orchestrator prefers in-process `run_deep_analyze_pipeline` when available for efficiency.
- Retries with exponential backoff on failure; records failed rows for requeue or inspection.
- Job state persisted to `SESSION_PERSIST_DIR/backfill_jobs/{assessment_id}.json` for audit.

UI integration:
- Poll status endpoint to display ribbon and ETA.
- Provide `Pipeline view` to sort by `triage_score` and color rows by triage + confidence.

Testing:
- Unit tests should mock `_get_assessment_cached` to feed fake assessments and validate selection logic and job state transitions.
- Integration tests should ensure status endpoint reflects progress after a short run.
