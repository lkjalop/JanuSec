## Pilot Validation Checklist

1. Environment
   - [ ] FAST_LIVE_MODE=1 set
   - [ ] SLACK_WEBHOOK_URL configured (or intentionally unset for dry run)
   - [ ] RULES_CONFIG_PATH present (optional) and loaded (verify rule weight change reflects in metrics after ingest)
2. Ingestion
   - [ ] POST /api/v1/endpoints/log_batch returns accepted > 0
   - [ ] /metrics shows events_ingested_total increasing
3. Classification
   - [ ] decisions_total increments for OBSERVE and ALERT scenarios
   - [ ] Ambiguity band exercised (inject events scoring ~0.5)
4. Alerting
   - [ ] ALERT event triggers Slack message (or DLQ entry if webhook invalid)
   - [ ] Dedup prevents identical alert replay within TTL
5. Correlation
   - [ ] /api/v1/correlation/stats shows non-zero tracked hosts after replay
6. Sanitized Egress
   - [ ] /api/v1/events/sanitized returns recent events with truncated cmdline
7. Replay Harness
   - [ ] scripts/log_replay reproduces same counts and metrics trend
8. Metrics Sanity
   - [ ] No rapid growth in ingest_validation_errors_total
   - [ ] ingest_buffer_size remains within expected bounds (< 80% of EVENT_BUFFER_MAX)
9. Rule Tuning
   - [ ] Editing external weight file changes subsequent decision distribution without restart
10. Post-Test
   - [ ] DLQ inspected and emptied (if needed)

Sign-off requires all boxes checked or deviation documented.