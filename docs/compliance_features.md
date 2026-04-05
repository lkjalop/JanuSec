Compliance Features and Flags

- Pro PDF (TitanAI-style)
  - Endpoint: `/api/v1/compliance/report/titanai`
  - Payload: `{ assessment_id, organization?, auditor?, executive_summary?, ai_insights?: string[] }`
  - Always available (uses reportlab). No external ML dependencies.

- Advanced Pro (TitanAI generator)
  - Endpoint: `/api/v1/compliance/report/titanai/advanced`
  - Enable: set `ENABLE_TITANAI_ADVANCED_PRO_REPORT=1`
  - Requires local module `dump/titan-ai/comprehensive_report_generator` and its ML deps.
  - Graceful fallback: returns `501 advanced_pro_report_disabled` if not enabled/installed.

- Executive Summarizer
  - Endpoint: `/api/v1/compliance/summarize`
  - Configure provider via env `COMPLIANCE_SUMMARIZER`:
    - `ollama` (default dev): uses `OLLAMA_HOST` (default http://localhost:11434) and `OLLAMA_MODEL` (default `llama3`).
    - `hf`: local Hugging Face pipeline; set `COMPLIANCE_HF_MODEL` (default `facebook/bart-large-cnn`).
    - `disabled` or unset: passthrough.
  - Optional classifier tags (SEC-BERT/CyBERT): set `COMPLIANCE_CLASSIFIER_MODEL` to a local HF model id.

- Taxonomy Expansion
  - Loader auto-expands skeleton catalogs to full index coverage for ISO 27001 (Annex A, 93 controls) and SOC2 CC (families CC1..CC9) with placeholder titles.
  - Public frameworks (NIST CSF / NIST AI RMF) can be added under `taxonomy/data/` as full JSONs and will be merged automatically.

