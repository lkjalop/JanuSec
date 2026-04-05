# Enabling KEV / Vulnerability Enrichment

Overview
- The platform can augment artifacts and findings with vulnerability context (KEV, EPSS, CVSS) via `src/integrations/vuln_enrichment.py` and related helpers.

Prerequisites
- Access to a KEV/KEV-like feed or vulnerability database (commercial or public feeds).
- API credentials or local feed files mounted into the runtime.

Steps
1. Configure feed access: set `KEV_FEED_URL` and credentials (e.g., `KEV_API_KEY`) in environment variables or your secrets store.
2. Ensure `src/integrations/vuln_enrichment.py` is configured to read those env vars. If not, patch the module to accept configuration from `os.environ` or `src/core/configuration`.
3. Restart the server. Verify enrichment by calling the SBOM/vuln endpoints (e.g., `POST /api/v1/sbom/upload` then `GET /api/v1/sbom/vulns?sbom_id=...`).

Notes
- For offline demos, create a small JSON file mapping package names to CVE/KEV metadata and point the service at that file.
