## Platform Confidence Assessment (CVSS/VPR + Hopgraph/EWMA/TF‑IDF)

This summary captures what was validated and where confidence stands after integrating CVSS/VPR and running targeted checks across graph, EWMA, and TF‑IDF features.

What works reliably
- SBOM ingestion and vulnerability surfaces
  - Upload → VEX application → Enrichment (KEV/EPSS/VPR) → Explainability (STRIDE/DREAD/MAESTRO) → UI render (CVSS/VPR columns, filters).
  - Tests: `tests/test_sbom_endpoints.py`, `tests/test_tenable_vpr_enrichment.py`.

- CVSS persistence and visibility
  - `cvss_max` persists across restarts; `vuln:cvss_max:<n>` factor emitted without scoring impact.
  - Tests: `tests/test_cvss_max_persistence.py`, `tests/test_sbom_vuln_mapper.py`.

- Correlation engine (vuln‑aware + core patterns)
  - `vuln:cvss_ge_9` + egress/beacon/LOLBin factors produce expected composite correlation factors.
  - Tests: `tests/test_vuln_corr_rules.py`, `tests/test_correlation_rules_basic.py`, `tests/test_correlation_rules_extended.py` (existing).

- Hopgraph basics
  - Graph construction and baseline operations validated by `tests/test_hopgraph_basic.py` (passed).
  - No regressions from CVSS/VPR changes observed in graph tests executed.

- EWMA adaptive detector
  - `tests/test_ewma_adaptive.py` passes; EWMA remains functional after changes.

- TF‑IDF LOLBin factor path
  - Tokenizer and basic TF‑IDF factors validated by `tests/test_lolbin_tfidf_basic.py`, `tests/test_lolbin_tfidf_tokenizer.py`.
  - New vuln‑aware rule combining TF‑IDF LOLBin with `vuln:cvss_ge_9` validated by `tests/test_vuln_corr_rules.py`.

Integrations confidence
- Tenable & Qualys stubs
  - Endpoints respond as expected (config/status/sync). Tenable VPR integrates into SBOM results.
  - Tests: `tests/test_qualys_tenable_endpoints.py`, `tests/test_tenable_vpr_enrichment.py`.

Known limitations / next improvements
- Stubs are offline demos; for production enable credentials vaulting, scheduled polling, rate limiting, and network error backoffs.
- SBOM UI: VPR >= 9 filter is injected at runtime due to a minor encoding quirk in the CVSS label region. Consider normalizing template encoding and moving the checkbox into static markup.
- Decision propagation: `vuln_context` is attached via stage metadata and merged before risk scoring. If needed, persist this field explicitly in decision stores for analytics.

Overall confidence rating
- High for the present demo scope and unit coverage. Core features (SBOM → Explain → Enrichment → Correlation → UI) are integrated and tested, with no regressions observed in Hopgraph, EWMA, or TF‑IDF flows relevant to the change.

