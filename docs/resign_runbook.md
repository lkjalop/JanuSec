Resign Job Runbook

Overview:
- When rotating signing keys for audit exports, historic exported reports need
  to be re-signed with the new key to preserve a single active signature
  scheme for investigators.

Steps:
1. Provision or ensure access to KMS/Key Vault and add new key metadata to keystore
   via the admin API `/api/v1/admin/verify/keystore/add` with wrap='kms' or 'azure'.
2. Validate that `resolve_key_plaintext(new_key_id)` returns the expected plaintext
   (use test-mode or mocks in staging).
3. From admin UI or curl, call `/api/v1/admin/verify/keystore/rotate` with `resign=true`.
   The endpoint returns a `job_id` for tracking.
4. Monitor job status via `/api/v1/admin/verify/keystore/rotate_job_status/{job_id}`.
5. Once job completes, verify a sample of re-signed exports using `scripts/verify_approval_audit.py --verify-file`.

Notes:
- The worker uses Redis (RESIGN_JOBS_REDIS_URL) if available. For small fleets a
  filesystem queue (data/resign_jobs) is used as fallback.
- Ensure backups of original exports are kept before mass re-signing.
