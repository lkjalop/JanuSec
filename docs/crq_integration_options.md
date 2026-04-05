# Cyber Risk Quantification (CRQ) Integration — Non-Invasive Adapter for Tier 1/2 LLM Summaries

Goal: Add CRQ context to Tier 1 and Tier 2 LLM summaries without changing existing pipeline scoring math. Provide optional human comments per flagged event and route summaries to persona-specific reports.

---

## Design Principles

- Non-invasive: No changes to core scoring, factor synthesis, or DREAD math.
- Pluggable: CRQ computed in an adapter layer reading existing decision outputs.
- Explainable: CRQ includes method, inputs, and rationale for auditability.
- Human-in-the-loop: Optional analyst comment per event/theme influences confidence.
- Persona-aware: Route summaries to the right audiences with tailored granularity.

---

## CRQ Adapter Options

1) FAIR-lite (quant) overlay
- Compute risk as $R = L_{EF} \times PLM$, where $L_{EF}$ (loss event frequency) is derived from recent event rates and $PLM$ (probable loss magnitude) from asset criticality + data sensitivity.
- Inputs: asset tier, data class, control efficacy, event volatility, historical incidents.
- Output: numeric risk + band (low/med/high) with explainability.
- Pros: Business-friendly numeric framing; maps cleanly to GRC.
- Cons: Requires priors; may feel approximate without historical calibration.

2) DREAD-weighted banding (non-quant)
- Use existing DREAD components to derive a severity band with governance caps (e.g., limit escalation if exposure is low).
- Inputs: pipeline DREAD/ATT&CK context + asset criticality.
- Output: band + rationale, no currency estimates.
- Pros: Simple; reuses existing context; minimal overhead.
- Cons: Subjective; can drift if not calibrated against outcomes.

3) CVSS bridge (vuln-linked events)
- For events with SBOM/vuln context, use CVSS base score with environment modifiers and asset importance.
- Output: numeric 0–10 + mapped band; includes exploit maturity and exposure.
- Pros: Standardized; auditors understand it.
- Cons: Not all threats are vulnerability-driven; can over-signal.

4) Bayesian conf + business impact blend
- Compute $R = w_1 \cdot Conf_{model} + w_2 \cdot Impact_{business} + w_3 \cdot Exposure_{control}$.
- Inputs: model confidence, impact (data class, SLA, revenue), control exposure.
- Output: normalized 0–1 risk + band.
- Pros: Flexible; tunable; transparent.
- Cons: Needs governance for weights to avoid gaming.

Recommendation: Start with DREAD-weighted banding + FAIR-lite overlay for high-value assets, gated by persona.

---

## Human Comment Capture (Optional)

- UI: Add an optional “Analyst Note” per event/theme (Tier 1/2).
- Storage: Persist under incident aggregator with fields: `comment`, `actor`, `timestamp`, `impact_tag`.
- Influence: Adjust confidence by small delta (e.g., ±0.05) or attach as evidence only; avoid changing core math.
- Audit: Include in report’s evidence section with immutable trail.

---

## Persona Routing

- Tier 1 SOC: concise band + next-best action; noisy signals suppressed.
- Tier 2 SOC: band + inputs + rationale; enable override + comment.
- GRC Auditor: FAIR-lite numeric + control mapping + evidence references.
- CISO/Exec: trendlines, top risks, controls efficacy delta, material impact.
- App/Service Owner: asset-specific guidance, remediations, ticket hooks.

---

## Framework Crosswalk (Evidence Mapping)

- SOC 2: CC series (CC1–CC9); map CRQ inputs to control effectiveness and incident handling evidence.
- PCI DSS: Requirements 6 (secure systems), 10 (logging), 11 (test), 12 (policy); show event->control reasoning.
- HIPAA: Security Rule (164.3xx); data class + access controls + incident traceability.
- GDPR: Art. 5/24/32; privacy-by-design; data class + exposure + mitigation.
- ISO 27001: Annex A controls; incident mgmt, logging, access control, supplier.
- ISO 42001: AI governance lifecycle, provenance, risk mgmt, auditability.
- NIST RMF & AI RMF: context, risk identification, measurement, treatment; include CRQ rationale + confidence.

Output schema can include `compliance_evidence`: control IDs, artifacts, timestamps, and rationale.

---

## Non-Invasive API Hooks (Examples)

- Extend incident summary (no math changes):
  - Add `crq` block: `{ method, score, band, inputs, rationale }`.
  - Add `human_comment`: `{ text, actor, timestamp, impact_tag }`.
  - Add `persona_routes`: `{ tier1, tier2, grc, exec, owner }` with report URLs.

- Suggested endpoints (optional):
  - `POST /api/v1/crq/score` — compute CRQ for an event/incident (reads existing decision payloads).
  - `POST /api/v1/incidents/{id}/comment` — store analyst note.
  - `GET /api/v1/reports/{persona}/{id}` — persona-specific summary view.

---

## Pros & Cons of Changing Core Math

- Changing DREAD/pipeline now
  - Pros: Potentially tighter alignment between CRQ and base scoring.
  - Cons: Risk of regressions, false positives/negatives, demo instability, re-tuning needed.
- Overlay CRQ adapter (recommended)
  - Pros: Safe; reversible; tunable; explainable; persona-specific.
  - Cons: Requires clear governance to prevent duplication/conflicts with base severity.

---

## Implementation Steps (Minimal)

1) Define `crq` schema; store alongside incident summaries.
2) Implement CRQ adapter (DREAD-band + FAIR-lite for high-value assets).
3) Add optional `human_comment` capture in UI + endpoint.
4) Generate persona-specific summaries; reuse existing report plumbing.
5) Calibrate bands with historical outcomes; log overrides for learning.

---

## Calibration & Governance

- Start with baseline weights; run shadow mode comparisons vs. current severity.
- Weekly calibration review: false positives/negatives, override frequency, control efficacy.
- Document method and inputs for auditors; version and change-log CRQ configs.

---

## Enterprise Expectations & Human Comments (NLP)

### Enterprise Expectations (Actionability & Audit)
- Governance: Clear method disclosure (`crq.method`, inputs, version). Changes logged and reviewable.
- Security: Role-based access for comment creation/edit; immutable audit trail (append-only with actor/timestamp).
- Compliance: Evidence mapping (`compliance_evidence`) to SOC 2/PCI/HIPAA/GDPR/ISO 27001/42001/NIST RMF/AI RMF.
- Process: Defined escalation SLOs per persona (Tier1/Tier2/GRC/Exec/Owner) and ticketing hooks.
- Stability: No changes to core scoring math until calibration milestones are met; CRQ overlay only.
- Observability: Metrics on override rates, comment usage, CRQ drift vs. base severity, time-to-escalation.

### Human Comment Lifecycle
- Capture: Optional per event/theme with fields `{text, actor, role, timestamp, impact_tag, suggested_action}`.
- Review: Tier 2 can endorse or contest comments; status transitions `{proposed, endorsed, contested, archived}`.
- Influence: Default evidence-only; optional small confidence delta (±0.05) when `endorsed` and policy allows.
- Retention: Configurable retention with privacy controls (PII scrub, redaction) and export to audit reports.

### NLP Integration Options for Comments
1) Tagging & Summarization (low risk)
   - Extract structured tags: `asset`, `data_class`, `mitre_technique`, `suspected_vector`, `recommended_action`.
   - Summarize to 1–2 sentences for Tier 1/Exec views; keep original text for Tier 2/GRC.
   - Pros: Improves readability and routing; minimal bias risk.
   - Cons: Requires taxonomy governance; avoid auto-influence on scoring.

2) Classification (moderate risk)
   - Classify comment into predefined categories (e.g., `false_positive`, `needs_investigation`, `policy_violation`).
   - Use as a signal to prioritize queues; do not change severity directly.
   - Pros: Helps triage; maps to workflows and tickets.
   - Cons: Must monitor for model drift and annotator bias.

3) Policy Extraction (higher complexity)
   - Identify control references, exceptions, and required attestations; auto-link to `compliance_evidence`.
   - Pros: Valuable for auditors; reduces manual mapping effort.
   - Cons: Needs careful validation to avoid incorrect compliance claims.

Recommendation: Start with tagging/summarization, add classification after calibration, use policy extraction selectively for GRC workflows. Keep NLP influence separate from core severity; treat NLP outputs as routing and evidence aids.

### Existing Platform Hooks to Leverage
- Recommendation actions: `POST /api/v1/incidents/{id}/recommendations/act` stores action status (`{id,domain,action,priority,status,updated_ts}`).
- Incident aggregator: Extend with `human_comments` array and `crq` block without altering existing shapes used by LIVE/SBOM/CSV.
- Telemetry & calibration: Use `/api/v1/admin/factors/telemetry` and `/api/v1/admin/factors/calibration*` for monitoring/comment influence policy.

### Impact on AI/ML Adaptive Learning
- Shadow mode feedback: Ingest `human_comments` and `recommendation_actions` as labeled outcomes for future calibration.
- Guardrails: Comments should not immediately alter model parameters; influence limited to confidence delta after endorsement.
- Weekly learning loop: Aggregate overrides, contested comments, and resolution outcomes; update CRQ adapter thresholds, not base math.
- Bias & privacy: Apply PII scrubbing, role-aware access, and differential weighting to avoid single-analyst bias.

### Data Model Additions
- `human_comments`:
  ```json
  {
    "comments": [
      {
        "text": "Observed benign backup traffic; suppress.",
        "actor": "analystA",
        "role": "Tier2",
        "timestamp": 1735880000,
        "impact_tag": "false_positive",
        "suggested_action": "close",
        "status": "endorsed"
      }
    ]
  }
  ```
- `crq` block example (unchanged severity influence):
  ```json
  {
    "crq": {
      "method": "dread_band+fair_lite",
      "score": 0.42,
      "band": "medium",
      "inputs": {"asset_tier": "gold", "data_class": "PII", "event_rate": 12},
      "rationale": "Medium DREAD with moderate loss magnitude; controls partially effective"
    }
  }
  ```

### Overengineering Risk & Framework Balance
- Using all models (DREAD/STRIDE/PASTA/MAESTRO/DIAMOND) per event can add complexity and raise false positives.
- Practical balance: Use DREAD for banding and ATT&CK/STRIDE for context; apply PASTA/MAESTRO at campaign/incident level, not every event.
- FAIR-lite only for high-value assets and auditor personas; keep quant optional.

### Enterprise SLAs & Reporting
- Tier 1: 5–10 minute triage SLA; comment summarization; actionable next steps.
- Tier 2: 30–60 minute deep-dive; endorsement/contest workflow; evidence compilation.
- GRC: Weekly CRQ rollups, control efficacy dashboards, audit-ready evidence bundles.
- Exec: Monthly trendlines, top risks, ROI of controls, material impact summary.
