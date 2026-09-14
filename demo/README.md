Demo: Multi-source Correlation (CSV HopGraph)

Overview
--------
This demo shows a small, reproducible multi-source correlation that reconstructs an attack path across 6 domains: Endpoint, Network (DNS), Cloud, Email, Data Store, and API. The front-end `csv_multi_analyzer.html` (LIVE console) can upload these CSVs, or you can run the provided automation script `demo/build_demo_session.py` to upload files and build a HopGraph session.

Files
-----
- `demo/datasets/endpoint_processes.csv` - suspicious processes and hashes
- `demo/datasets/network_dns.csv` - DNS NXDOMAIN spikes and candidate exfil domains
- `demo/datasets/cloud_api_calls.csv` - IAM modifications and suspicious S3 uploads
- `demo/datasets/email_phishing.csv` - phishing messages with malicious attachments
- `demo/datasets/data_store_access.csv` - large SELECTs and potentially exfiltrating queries
- `demo/datasets/api_gateway_logs.csv` - unusual API exports and suspicious client IPs

Quick Start (server already configured for demo)
------------------------------------------------
1. Start the server (start_server.bat already sets demo envs):

```powershell
start_server.bat
```

2. Open the LIVE console at `http://localhost:8080/` and navigate to "Multi-Source Correlator" or open `frontend/static/csv_multi_analyzer.html`.

3. Upload all six CSV files via the UI and use the mapping presets (EDR / DNS / Cloud / Email / Data / API) to map canonical fields. Click `Build HopGraph` to construct a session and view the overlap matrix and graph.

	Important: The UI (and automation script) requires the correlation header to generate session IDs. When uploading manually (outside the provided page), include `X-Correlation-Analyze: true`. The automation script sets this automatically.

Automation
----------
A helper script `demo/build_demo_session.py` is included to automate uploads and session build. It uses the local API key from `localStorage` in the browser or the server's generated API key printed on startup. You can run it from the repo root with your virtualenv active.

Environment variables for `demo/build_demo_session.py`:
- `DEMO_API_BASE`: override API base URL (default `http://localhost:8080`)
- `DEMO_API_KEY`: optional API key to send in `x-api-key` header
 - Uses `/health` endpoint for readiness check before uploads.

What the demo illustrates
-------------------------
- Cross-domain correlation: same source IP / user / file hash observed across endpoint, API, and cloud events.
- NXDOMAIN-based exfil signals aligning with large S3 uploads and database export queries.
- Playbook resolution for `cloud_breach_playbook` and an auto-generated investigative narrative (LLM summarization enabled for the demo).

Notes & Troubleshooting
-----------------------
- If LLM summaries are not desired, set `LLM_SUMMARIES_ENABLED=0` and restart the server.
- The demo relies on `TEST_HELPERS_ENABLED=1` for deterministic fixture behavior. This is set in `start_server.bat`.
- If `start_server.bat` generated an API key on startup, copy it from the console output and paste into the browser with `localStorage.apiKey = '<API_KEY>'` then reload the UI.
 - If uploads succeed but no HopGraph session builds, verify the `X-Correlation-Analyze: true` header was sent (network tab) and that `session_ids` appear in the upload JSON response.
