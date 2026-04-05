Metrics Publisher

To enable best-effort metric event publishing to a message bus, set the following environment variables:

- `METRICS_PUBLISH_ENABLED=1` — enable publishing.
- `METRICS_PUBLISH_REDIS=redis://host:port/db` — optional Redis DSN; publishes JSON to channel `metrics.events`.
- `METRICS_PUBLISH_KAFKA=broker1,broker2` — optional Kafka bootstrap brokers; publishes to topic `metrics.events`.

Example (Linux / macOS):

```bash
export METRICS_PUBLISH_ENABLED=1
export METRICS_PUBLISH_REDIS=redis://localhost:6379/0
# or
export METRICS_PUBLISH_KAFKA=localhost:9092
```

The publisher is best-effort and will not raise on failures; use it only when you have the correct infra configured.
