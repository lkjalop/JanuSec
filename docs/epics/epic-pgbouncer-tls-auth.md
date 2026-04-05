Title: PgBouncer TLS/auth flow + readiness

Context
- Current PgBouncer manifest is minimal; needs TLS upstream support, managed secrets, health probes.

Scope
- Add Secret template for DB credentials (or support existingSecret) and optional CA/cert/key for TLS to Postgres.
- Add liveness/readiness probes (auth_query) and config for server_tls_sslmode.
- Provide example values and doc updates.

Acceptance Criteria
- PgBouncer connects to Postgres using TLS when enabled; secret rotation instructions included.
- Readiness probe gates traffic until pool is healthy.
- Chart values validated via helm lint + template tests.

