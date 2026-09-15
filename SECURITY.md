# Security

JanuSec is a development preview, not a certified production security boundary.

## Reporting

Use [GitHub private vulnerability reporting](https://github.com/lkjalop/JanuSec/security/advisories/new)
for security findings. Do not include credentials, customer logs or personal data
in public issues. Provide a minimal synthetic reproduction and the affected commit.
No response-time service level is currently promised.

## Deployment requirements

- Use explicit tenant-bound authentication and least-privilege scopes.
- Keep secret stores, encryption keys, token payloads and runtime databases outside
  version control. Use a managed Vault or Azure Key Vault backend for deployments.
- Local preview credentials are public examples and must never authorize a public service.
- Stop file-store users before offline encryption-key rotation and restart them afterward.
- Treat any publicly exposed key and ciphertext as compromised. Re-encryption does
  not revoke the underlying provider access or refresh tokens.
- Never claim a control failed solely because a technique maps to it.

See [key rotation](docs/tenant_store_key_rotation.md). Historical Git copies can
retain removed data; changing a branch does not revoke an exposed credential.
