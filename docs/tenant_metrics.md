Tenant metrics guidance

When enabling tenant-level labels for Prometheus metrics you must take care to avoid cardinality explosions.

Recommended configuration patterns:

- Whitelist a small set of tenants for verbatim labels:
  TENANT_METRICS_WHITELIST=acme,bluecorp

- Use hashed buckets for the rest to keep cardinality bounded:
  TENANT_METRICS_HASH_BUCKETS=20

- Or sample a small percentage of tenants to inspect labels during rollout:
  TENANT_METRICS_SAMPLE_RATE=0.01

- Master switch to enable/disable tenant labels:
  ENABLE_TENANT_METRICS=0

Start with ENABLE_TENANT_METRICS=0 and only enable when the whitelist/buckets are configured. The server logs a warning on startup if this flag is enabled.
