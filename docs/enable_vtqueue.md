# Enabling VirusTotal (VTQueue) Integration

Overview
- The project includes optional VT lookup and queuing helpers under `src/artifact/vt_queue` and endpoints in `src/api/email_security_endpoints.py`.

Prerequisites
- Obtain a VirusTotal API key with the required endpoints enabled.
- Ensure network egress to VirusTotal from the runtime environment.

Steps
1. Set env var `VT_API_KEY` to your VirusTotal API key in the service environment.
2. Confirm the `src/artifact/vt_queue` module is present and importable. If it's a custom service, ensure any background worker process is started.
3. Optionally enable a config flag: `ENABLE_VT_QUEUE=1` (if present in your deployment config).
4. Restart the server and check `/api/v1/email/security/vt/status` or review logs for successful VT lookups.

Notes
- For demos without a real VT key, implement a small mock service that returns pre-canned responses and set `VT_API_KEY=mock`.
