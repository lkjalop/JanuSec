from prometheus_client import Counter, Histogram, Gauge

events_ingested_total = Counter(
    "connector_events_ingested_total",
    "Total events ingested",
    ["connector"],
)

ingest_errors_total = Counter(
    "connector_ingest_errors_total",
    "Total ingestion errors",
    ["connector", "code"],
)

retry_attempts_total = Counter(
    "connector_retry_attempts_total",
    "Total retry attempts",
    ["connector"],
)

ingest_latency_seconds = Histogram(
    "connector_ingest_latency_seconds",
    "Latency of ingest operations",
    ["connector"],
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10),
)

queue_depth = Gauge(
    "connector_queue_depth",
    "Current queue depth",
    ["connector"],
)
