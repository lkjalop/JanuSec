# CVSS Integration Verification

This document verifies the end-to-end CVSS exposure in the platform, including storage, factor emission for visibility, SBOM UI display, and API enrichment.

Scope verified
- cvss_max persistence in SBOM aggregation repository.
- Non-scoring factor emission: `vuln:cvss_max:<n>` for SSE/timelines.
- SBOM API preserves CVSS and merges Tenable VPR (best-effort).
- SBOM UI renders CVSS and VPR columns and supports filtering.
- Correlation rules consume `vuln:cvss_ge_9` and fire composite patterns.

Files and behavior
- `src/repositories/sbom_vuln_agg_repo.py`
  - Tracks `cvss_max` per `(tenant, component_key)` and persists via JSONL.
  - Verified by `tests/test_cvss_max_persistence.py` (reload retains 9.8).
- `src/modules/sbom_vuln_mapper.py`
  - Emits `vuln:cvss_ge_9` when `cvss_max >= 9.0` and a non-scoring `vuln:cvss_max:<n>` factor for visibility.
  - Enforces confidence cap; scaling verified by `tests/test_sbom_vuln_mapper.py`.
- `src/api/sbom_endpoints.py`
  - For `GET /api/v1/sbom/vulns`, merges Tenable VPR via `tenable_client.CLIENT.get_vpr_for_cves()`; CVSS present as `cvss` or `cvss_base_score`.
- `frontend/static/sbom.html`
  - Adds VPR column and explain panel VPR field; filtering for `VPR >= 9` injected at runtime to avoid encoding quirks.
- `src/core/correlation/hunt_correlation.py`
  - Vulnerability-aware correlations trigger on `vuln:cvss_ge_9` alongside egress/beacon/LOLBin factors.

Tests executed (all passing)
- `tests/test_cvss_max_persistence.py`: cvss_max persists across reloads.
- `tests/test_sbom_endpoints.py`: SBOM upload/VEX flow returns expected structure.
- `tests/test_sbom_vuln_mapper.py`: cap behavior and factor presence.
- `tests/test_vuln_corr_rules.py`: vuln-aware correlations fire as designed.
- `tests/test_tenable_vpr_enrichment.py`: Tenable config seeds VPR, SBOM vulns reflect VPR score.

Confidence
- High. CVSS is persisted, visible to users via factors and UI, and participates in correlations through `vuln:cvss_ge_9` without unintended scoring side effects from the non-scoring `vuln:cvss_max:<n>` factor.

