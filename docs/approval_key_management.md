Approval HMAC Key Management and Rotation
======================================

This document describes recommended approaches to manage the HMAC key used to sign approval-event exports and verify the audit chain.

1) Key storage options
  - Plaintext env (DEV/CI): set `APPROVAL_AUDIT_HMAC_KEY` in your environment. Not recommended for production.
  - AWS KMS (recommended for AWS): store a plaintext HMAC key locally encrypted with KMS, then set `APPROVAL_AUDIT_HMAC_KMS_CIPHERTEXT` to the base64 of the ciphertext blob. The verify script will call `kms.decrypt` to retrieve the plaintext. Ensure the service role has `kms:Decrypt` for the key.
  - Azure Key Vault: set `APPROVAL_AUDIT_HMAC_AZURE_SECRET_NAME` and `AZURE_KEYVAULT_URL`. The service principal or managed identity must have `get` access to the secret.

2) Key rotation (wrap/unwrap flow)
  - Rotation using envelope encryption (recommended):
    - Generate a new random HMAC key locally (e.g., 32 bytes) and encrypt it with the KMS key (AWS) or wrap with Key Vault.
    - Store the ciphertext in configuration (e.g., `APPROVAL_AUDIT_HMAC_KMS_CIPHERTEXT`) and deploy to services.
    - Re-sign any exported reports if you need to maintain a single global signature key. Alternatively, include the key id and signature algorithm in the exported report metadata so verifiers can pick the correct key.

3) Operational considerations
  - Key access control: restrict which identities can call KMS decrypt or Key Vault get. "Admin" service roles should be narrowly scoped.
  - Key rotation schedule: quarterly or per policy; automate with a pipeline that generates ciphertext and updates config.
  - Signature metadata: export reports should include `generated_at` and optional `key_id` so downstream verifiers can locate the appropriate key material.

4) Verifying historic exports after rotation
  - Store the prior key material encrypted in a vault accessible to auditors, or include `key_id` and have the verifier ask the KMS/KeyVault for the appropriate key.

5) Example (AWS envelope encryption)
  - Generate key locally: `openssl rand -hex 32 > hmac.key`
  - Encrypt with KMS: `aws kms encrypt --key-id alias/my-approval-key --plaintext fileb://hmac.key --output text --query CiphertextBlob | base64 --decode > hmac.ct` (store base64 of hmac.ct as `APPROVAL_AUDIT_HMAC_KMS_CIPHERTEXT`)

6) Example (Azure Key Vault)
  - Set secret: `az keyvault secret set --vault-name myVault --name approval-hmac-key --value "$(cat hmac.key)"`
  - Set `APPROVAL_AUDIT_HMAC_AZURE_SECRET_NAME=approval-hmac-key` and `AZURE_KEYVAULT_URL=https://myVault.vault.azure.net`

7) Auditing and proof
  - Keep an access log for KeyVault/KMS decrypts; combine with application audit logs to show who verified or exported which reports.
