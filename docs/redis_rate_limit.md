Redis Deployment Guidance for Rate-Limiter
=========================================

This project supports a Redis-backed rate limiter and job queue for distributed
operation. Configure production deployments as follows:

- Environment variable: `RATE_LIMIT_REDIS_URL` (e.g. `redis://:password@redis-1.example:6379/0`)
- For ARC queue and resign jobs the code reads `REDIS_URL` / `ARC_VERIFY_*` keys; set them consistently.
- Ensure Redis is highly available:
  - Use Redis Cluster or a managed Redis service (Azure Redis, AWS ElastiCache Redis Cluster)
  - Configure TLS and authentication (ACLs) and network-level restrictions (VPC)
  - Use replication + automatic failover; keep persistence (AOF/RDB) tuned for your service-level objectives

Operational notes:
- When Redis is not available, the application falls back to local in-process queues and local job files
  (`data/resign_jobs`). This is suitable for single-node or dev deployments, but will not scale.
- Monitor queue depth and DLQ (`arc:verify:dlq`) for stuck jobs; use `ARC_VERIFY_*` env vars to tune keys.
- Set `VERIFY_RATE_LIMIT_PER_MIN` to control per-actor throtlling; the RateLimiter will use Redis counters when
  `RATE_LIMIT_REDIS_URL` is set.

Security:
- Do not store plaintext keys in the keystore. Prefer wrapping keys in KMS/Azure Key Vault and store only
  references in `data/approval_keystore.json`.
