Key Rotation Procedure

1. Generate or provision new signing key in cloud KMS or Key Vault.
2. Add keystore metadata using admin API `/api/v1/admin/verify/keystore/add` (prefer metadata-only entries referencing wrapped ciphertext or vault secret).
3. Test resolution in staging by calling `scripts/verify_approval_audit.py --export --token <token> --key-id <new_key_id>`.
4. Trigger rotation with `/api/v1/admin/verify/keystore/rotate` (set `resign=true` to re-sign historic exports).
5. Monitor resign job and verify outputs.
6. Rotate consumer verification keys (if any) and update monitoring rules.

Env vars to set in production:
- RATE_LIMIT_REDIS_URL: redis://...
- RESIGN_JOBS_REDIS_URL: redis://... (optional; defaults to RATE_LIMIT_REDIS_URL)
- APPROVAL_KEYSTORE_PATH: path to keystore on disk (or use env map in CI)
