## Qualys & Tenable API Implementation (Demo Stubs)

This document describes and validates the added Qualys and Tenable integration endpoints and client stubs.

Endpoints
- Tenable
  - POST `/api/v1/integrations/tenable/config`
  - GET `/api/v1/integrations/tenable/status`
  - POST `/api/v1/integrations/tenable/sync`
- Qualys
  - POST `/api/v1/integrations/qualys/config`
  - GET `/api/v1/integrations/qualys/status`
  - POST `/api/v1/integrations/qualys/sync`

Clients
- `src/integrations/tenable_client.py`
  - Config: accepts `api_url`, `access_key`, `secret_key`, `enabled`, and optional `vpr_map` seed.
  - Status: reports enabled state, last_sync, cached VPR count.
  - Sync: stub; marks last_sync and preserves cache.
  - `get_vpr_for_cves(cves)`: returns VPR scores for requested CVEs from local cache.
- `src/integrations/qualys_client.py`
  - Config: accepts `api_url`, `username`, `password`, `enabled`.
  - Status: enabled state and last_sync.
  - Sync: stub; marks last_sync.

Routing considerations
- Static routes declared before the generic `/api/v1/integrations/{name}/config` to avoid scope interception.
- API key scope checks are enforced globally; in tests we send `x-api-key: devkey123` (which the auth layer maps to `*` during pytest).

SBOM VPR enrichment
- `src/api/sbom_endpoints.py`: best-effort merge of VPR into SBOM vulnerabilities as `vpr` and `vpr_score`.

Tests executed (all passing)
- `tests/test_qualys_tenable_endpoints.py`: config → status → sync flows.
- `tests/test_tenable_vpr_enrichment.py`: seeds Tenable VPR and confirms VPR present in SBOM vulns output.

Example usage (curl)
```
# Seed VPR for a CVE
curl -H "x-api-key: devkey123" -X POST \
  -d '{"enabled":true,"vpr_map":{"CVE-2025-0001":9.7}}' \
  http://localhost:8080/api/v1/integrations/tenable/config

# Upload SBOM referencing CVE-2025-0001
curl -H "x-api-key: devkey123" -H "content-type: application/json" -X POST \
  -d '{"components":[{"name":"libx","version":"1.0","cve":"CVE-2025-0001","cvss_base_score":9.0}]}' \
  http://localhost:8080/api/v1/sbom/upload

# Fetch enriched vulns (VPR included)
curl -H "x-api-key: devkey123" 'http://localhost:8080/api/v1/sbom/vulns?sbom_id=<id>'
```

Limitations
- These are offline/demo stubs; no external network calls are made in restricted environments.
- Production implementations should enforce secure credential storage and scheduled polling/backoff.

