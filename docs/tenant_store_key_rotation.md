# File-store encryption-key rotation

This procedure rotates Fernet encryption, not provider credentials. The older
`rotate_tenant_secret` helper updates a token payload and does not rotate its
master encryption key.

1. Identify every deployment and provider credential protected by the exposed key.
   Revoke/replace affected access tokens, refresh tokens and client secrets at their
   owning provider. Never paste token values into an issue or command line.
2. Stop every process using the file store, including workers and scheduled tasks.
3. Choose a recovery directory outside the repository, with access restricted to
   the operator. On Windows, configure its ACL before invoking the script.
4. Run `python scripts/rotate_tenant_store_key.py --store <store-directory>
   --backup <new-private-recovery-directory> --writers-stopped` as one command.
   The tool authenticates all ciphertext first, backs up originals, re-encrypts
   payloads, verifies them and emits a receipt containing no token or key bytes.
5. Restart all consumers, which load the new key. Verify token loading and provider
   authentication with the replacement credentials.

Rotation requires an offline maintenance window. It is not a transactional online
rotation protocol. If `.rotation-in-progress` remains after a crash, stop consumers
and restore the entire key/ciphertext set from the recovery copy before retrying.
Do not remove the marker to bypass an incomplete rotation. Retain the private
backup according to your incident recovery policy; it still contains exposed material.

For deployed systems prefer the supported Vault or Azure Key Vault backend. Merely
moving or encrypting old tokens cannot invalidate publicly recoverable copies.
