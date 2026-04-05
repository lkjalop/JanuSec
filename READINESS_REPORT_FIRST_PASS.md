# JanuSec Platform – Readiness Report (First Pass)

Date: 2025-10-04
Environment: Local (Windows), API at http://localhost:8080

## Summary

Core pipeline up, metrics present, SSE streaming OK. Network/endpoint scenarios executed successfully. Endpoint rules did not fire in this minimal run (verdict IGNORE, score 0.0), which suggests rules engine defaults didn’t match our synthetic payload; baselines and clustering also did not produce explicit factors in the quick network test. Prometheus metrics include risk histogram and SSE counters. Demo validator reports readiness OK.

Overall: Partially ready – core scaffolding healthy, detection tuning likely needed for production-grade efficacy.

## What ran

- Health: /api/v1/health – OK
- Demo validator: health, ingest (8 events), metrics, SSE, frontend mounts – PASSED
- Endpoint scenario (LOLBin lineage, PowerShell spawned by Word)
  - POST /api/v1/endpoints/log_batch with classify + include_rules + send_alerts
  - Result: accepted=1, alerts_emitted=1, verdict=IGNORE, score=0.0, rules=[]
- Network scenario (NXDOMAIN bursts for one host)
  - 40 DNS events with rcode=3
  - Result: accepted=40, sample_rules_detected=False, buffer_size≈41
- Metrics: /metrics present; contains risk_score_distribution and detection_sse_decisions_total

## Observations

- Health ➜ OK; DB health reported; decision cache size non-null.
- SSE stream ➜ OK; counters incrementing.
- Metrics ➜ risk histogram and SSE present.
- Endpoint detection ➜ rules didn’t trigger for the synthetic event; risk=0 indicates the rules engine either isn’t wired to trigger on our payload shape or requires specific fields.
- Network detection ➜ NX tracking/baselines didn’t surface explicit baseline: factors in the sample response; likely needs time/windowing or specific baseline config to mark anomalies.

## Gaps and recommended follow-ups

1) Rules engine coverage and payload alignment
- Ensure rules engine (rt.rules_engine) is initialized and has patterns for LOLBins/process lineage.
- Validate required fields for rules to match (e.g., process.command_line vs cmd, parent relationships).
- Add a small ruleset targeting the test payloads.

2) Baselines and NX anomaly visibility
- Confirm baseline store warm-up and thresholds; exercise enough normal vs abnormal to cross z-score thresholds.
- Validate that NX tracker is enabled (NX_RATE_TRACKER_ENABLED) and z-score signals are turned into baseline:* factors.

3) Alert semantics
- We observed 1 alert emitted although verdict=IGNORE; verify alert filters and dedup config so only meaningful alerts are emitted in production.

4) Production hardening checks (spot):
- Admin OIDC/session/CSRF flows – exercise UI and revoke + audit path.
- DLQ requeue-as – force an error path, validate audit + next_retry update and retry behavior.
- Backpressure & rate limits – provoke 503/429 and observe recovery.

## Pass/Fail snapshot

- API health & core endpoints: PASS
- Metrics & SSE presence: PASS
- Endpoint detection efficacy (LOLBin): NEEDS TUNING
- Network NX anomaly detection: NEEDS TUNING
- Alerts dedup/basic: PASS (no flood observed)

## Suggested next steps

- Add/enable a canonical rule for Office→PowerShell lineage (T1059) and re-run endpoint scenario; target score ≥ 0.7 with explicit factor(s).
- Warm baselines and replay NX bursts after a period of normal traffic to observe baseline:anomaly factors; tune thresholds if needed.
- Add a simple unit/integration test to assert risk histogram increments for non-zero scores.
- Run the full demo validator again, then Zeek replay and observe /sidepanel and /metrics during load.

---

Appendix A – Commands used

```powershell
.\.venv-1\Scripts\python.exe start_simple.py
.\.venv-1\Scripts\python.exe scripts\validate_demo.py --api http://localhost:8080
.\.venv-1\Scripts\python.exe scripts\run_scenarios.py --api http://localhost:8080
```
