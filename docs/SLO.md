Short SLO & Autoscale Guidance

Context
- These SLOs are based on stress test observations using `scripts/stress_ingest_test.py` against a local deployment.
- Observed behavior: at concurrency=10 measured p50 ≈ 2s (ingest pipeline), at concurrency≈48 p50 ≈ 8s and error rates (429) > 10%.
- Prometheus metrics scraped: ingest_buffer_size, ingest_decision_latency_seconds_(count|sum|bucket), detection_sse_decisions_total, rate_limit_dropped_total.

Service Level Objectives (SLOs)
1. Availability SLO (ingest endpoint): 99.9% successful responses (2xx) over a 7-day window.
   - Rationale: production should tolerate occasional transient load spikes without losing data.
2. Latency SLO (ingest pipeline end-to-end): p95 < 10s, p50 < 3s.
   - Rationale: p50 observed ~2s under light load; p95 should remain under 10s to keep UI and downstream alerts timely.
3. Error Budget for rate-limiting: keep 429 rate < 0.1% over rolling 24h.
   - Rationale: backpressure can indicate overload; frequent 429s degrades customer experience.

Recommended Autoscale & Guardrail Thresholds
- Pooling/Workers (CPU-bound components):
  - Scale-out when ingest_buffer_size > 500 or rate_limit_dropped_total rises > 1/min for 5 minutes.
  - Scale-in when ingest_buffer_size < 100 for 10 minutes.
- Ingress/API (replicas behind load balancer):
  - Add +1 replica when p95 request latency for /api/v1/ingest/batch > 8s for 2 consecutive 1-minute windows.
  - Remove -1 replica when p95 < 4s for 10 minutes and ingest_buffer_size < 100.
- Redis/Queue (durable buffer):
  - Alert when Redis length of queue > 10k or oldest message age > 1 hour.
  - Provision additional capacity or fast-path consumers when queue growth rate > 1000/min sustained for 5 minutes.

Backpressure & Failure Modes
- Short-term overload -> return 429 for new requests and rely on client-side exponential backoff.
- Durable queue (Redis) should be used to persist spikes without rejecting data; set a maximum queue retention to avoid unbounded growth.
- Recommended retry policy for DLQ: exponential backoff with jitter, max attempts=5, then send alert for manual review.

Operational Playbook (short)
- If 429s spike above 1%: scale up replicas and verify worker throughput; check CPU and GC metrics.
- If ingest_buffer_size grows: check workers for errors, check Redis liveness, and inspect `rate_limit_dropped_total`.
- If p95 latency grows > 12s: create temporary high-priority fast-path to accept small batches (reduce classification cost) and scale out.

How to measure
- Use Prometheus metrics exposed by the service. Key metrics:
  - ingest_buffer_size
  - ingest_decision_latency_seconds_bucket / _count / _sum
  - detection_sse_decisions_total
  - rate_limit_dropped_total

- Create Grafana dashboards for p50/p95 over time and a panel for queue length and oldest message age.

Notes
- These are starting guidelines. Run canary deployments and adjust SLOs based on real production traffic patterns.
