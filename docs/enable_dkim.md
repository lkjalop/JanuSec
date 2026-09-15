DKIM Cryptographic Verification (enable guide)

Overview

The project can perform cryptographic DKIM verification using the `dkimpy` library. The code will attempt to call `verify_dkim(raw_bytes)` when raw RFC822 message bytes are supplied in the `raw` object (field `raw_rfc822` or `raw_bytes_b64`) to `/api/v1/email/ingest`.

Steps to enable locally

1. Install the dependency into your Python environment:

```powershell
pip install dkimpy
```

2. Restart the server process so the `dkimpy` import is available at startup.

3. When sending emails to the ingest endpoint, provide either:
   - `raw.raw_rfc822` as a UTF-8 string containing the full RFC822 message bytes, or
   - `raw.raw_bytes_b64` as a base64-encoded byte string of the full message.

4. The endpoint will return `dkim_crypto` under the `email_signals` structure when cryptographic verification was possible; otherwise the `dkim` field will include an `error` hint (e.g., `dkimpy_not_installed`).

Notes

- If `dkimpy` is not installed, the system still parses DKIM header tokens (`d=` and `s=`) and emits `dkim.present` but will not cryptographically verify signatures.
- For consistent ingestion in automated collectors, ensure `raw_rfc822` or `raw_bytes_b64` is preserved.

Security

- DKIM verification requires raw message bytes. Avoid sending production PII to public test endpoints; run locally or in a secure environment.
