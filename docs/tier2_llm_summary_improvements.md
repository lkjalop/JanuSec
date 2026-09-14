# Tier 2 LLM Investigation Summary (Deep Dive) – Current Functionality & Improvement Guide

File Location (absolute on this workstation):
`d:\AI\Threat_thy_sniffer\frontend\static\csv_deep_analysis.html`
Frontend Route: `http://localhost:8080/static/csv_deep_analysis.html`
Primary JS Function Rendering Tier 2 Payload: `renderTier2Payload(payload)` inside the IIFE.
Long-form Generation Trigger: `generateLongSummary()` (60–120 line summary)
Tier 2 Generation Trigger: `generateTier2Investigation()` (POST `/api/v1/csv/tier2_investigate`)
Verification Trigger: `verifyDecision()` (POST `/api/v1/assessments/{assessment_id}/llm/verify`)

---
## 1. Current UX & Flow
1. Row hydration pulls cached artifact context from `localStorage.csv_last_results` using `csv_deep_row` index.
2. Long summary button calls `/api/v1/csv/long_summary` with parameters: domain, model override, `max_lines=120`, `include_mapping_semantics`, `include_diversity_weighting`.
3. Tier 2 Investigation button calls `/api/v1/csv/tier2_investigate` passing the entire row, optional `assessment_id`, optional `session_id`, and pipeline context.
4. Returned Tier 2 payload populates multiple panels (Executive Summary, Threat Level, Gaps, Evidence, Tasks, Alternatives, Entity Graph, Timeline, SIEM Queries, Threat Intel).
5. Caching: Tier 2 result stored in `localStorage` keyed by `tier2_{rowIndex}_{hash}` with age eviction at 60 minutes.
6. Domain profiling heuristic (`detectDomainProfile`) infers `endpoint`, `network`, or `generic` domain impacting context claims in prompts.
7. Running cost is incremented per call and displayed.
8. Verification merges HopGraph evidence and returns flags plus confidence / factors appended to existing summary text.

---
## 2. Current Tier 2 Payload Schema (Inferred)
Below is a consolidated JSON Schema style (informal) from accessed keys in `renderTier2Payload` and related logic.

```jsonc
{
  "executive_summary": {
    "recommended_action": "string",         // e.g. "Escalate" / "Investigate" / "Monitor"
    "one_liner": "string",                  // concise narrative
    "threat_level": "string"                // e.g. HIGH / MEDIUM / LOW / UNKNOWN
  },
  "mitre_mapping": {
    "kill_chain_phase": "string"            // e.g. "Execution", "Exfiltration"
  },
  "ai_reasoning": {
    "knowledge_gaps": ["string"],           // list of explicit gaps
    "supporting_evidence": [
      {
        "observation": "string",           // raw observation statement
        "significance": "string",          // why it matters / analytic value
        "confidence": 0.0                    // numeric 0..1
      }
    ],
    "alternative_hypotheses": [
      {
        "hypothesis": "string",            // alternate scenario
        "probability": 0.0,                  // numeric probability 0..1
        "evidence_needed": "string"        // missing evidence to confirm/disprove
      }
    ]
  },
  "investigation_tasks": [
    {
      "task": "string",                     // actionable task
      "tool": "string",                     // tool or data source
      "priority": "low|medium|high|critical"
    }
  ],
  "entity_graph": {
    "primary_entity": {
      "type": "string",                     // e.g. host, user, process
      "identifier": "string"
    },
    "related_entities": [
      {
        "relationship": "string",          // e.g. communicates_with, spawned, accessed
        "type": "string",
        "identifier": "string"
      }
    ]
  },
  "evidence_timeline": {
    "events": [
      {
        "timestamp": "ISO8601|string",    // event time
        "description": "string",           // narrative or event type
        "event_type": "string",            // optional separate type field
        "severity": "high|medium|low|info"
      }
    ]
  },
  "siem_queries": [
    {
      "name": "string",
      "platform": "string",                // e.g. splunk, sentinel, qradar
      "query": "string"                    // actual query text
    }
  ],
  "threat_intel": "string|dict|array",      // flexible structure (indicators, hits, metadata)
  "domain": "string",                        // derived: endpoint|network|generic
  "domain_confidence": 0.0,                   // numeric confidence
  "_tier2_internal?": {                       // (optional extension) internal debug/meta
    "prompt_tokens": 123,
    "completion_tokens": 456,
    "latency_ms": 789
  }
}
```

---
## 3. Current Prompt / Generation Characteristics
Although prompt text is not visible here, usage suggests:
- Single-pass large prompt combining raw row structure + pipeline context.
- Domain adaptation (endpoint vs network) changes descriptive focus.
- Output length targeted (60–100 lines) but freeform.
- Minimal structured formatting beyond sections extracted post-hoc.
- Confidence values likely heuristic or model-provided without calibration.

---
## 4. Improvement Areas (Strategic)
| Area | Current Gap | Recommended Enhancement |
|------|-------------|-------------------------|
| Structure & Readability | Raw paragraphs; mixed detail levels | Enforce hierarchical sectioning: Executive, Key Judgments, Evidence Table, Hypotheses, Gaps, Recommended Actions, Next 24h Plan |
| Actionability | Tasks exist but not tied to evidence & priority rationale | Introduce structured task objects: `{task, why, required_data, SLA_hours, owner_role}` and group by investigation phase |
| Confidence Calibration | Single numeric estimates without explanation | Provide `confidence_rationale`, adopt likelihood bands (Certain / Likely / Plausible / Unlikely) mapping numeric ranges |
| Evidence Quality | Lacks sourcing and chain-of-custody tags | Add `source_type` (EDR, DNS, Auth), `first_seen`, `last_seen`, `corroboration_count` |
| Alternative Hypotheses | Present but may be thin | Use explicit competing hypothesis framework: For each alt include `discriminating_evidence`, `collection_action` |
| MITRE Integration | Only kill chain phase | Add full technique list with detection coverage flag and gap annotation (`{technique_id, name, coverage: high|partial|none}`) |
| Threat Intel | Unstructured | Normalize to: `{indicator, type, reputation, first_seen, last_seen, hit_context}` |
| Timeline | Basic events | Add sequence indices, causal linkage hints (`preceded_by`, `enabled_by`), highlight pivot points |
| Entity Graph | Simple | Provide centrality metrics (degree, betweenness), anomaly scores, classification (asset criticality) |
| Query Generation | Static list | Multi-target query bundling & justification: attach expected result semantics & risk addressed |
| Domain Profiling | Heuristic factors | Replace with ML classifier or rule fusion including weighted factor vectors and threshold reasoning trace |
| Cost Visibility | Aggregated cost only | Include per-component token usage, cumulative vs cache-saved cost delta |
| Caching | Time-based only | Add digest-based semantic equivalence check; show stale vs changed diff summary |
| Verification Layer | Appends raw results | Insert a structured `verification_report` block summarizing evidence coverage, gaps, consistency checks |
| Narrative Quality | Model raw style | Apply post-generation rhetorical polish: active voice, remove filler, highlight imperative verbs |
| Bias / Hallucination Guard | Implicit | Add rule-based guard: flag unsupported claims (no evidence pointer) and route to re-verification subprompt |

---
## 5. Prompt Engineering Enhancements
1. Two-Phase Generation (Plan → Elaborate):
   - Phase 1: Model generates structured plan JSON (sections + bullet skeleton).
   - Phase 2: Expand each bullet with evidence references & action verbs.
2. Explicit Section Tokens: Delimiters like `<<EXEC_SUMMARY>>`, `<<EVIDENCE_TABLE>>` to decrease drift.
3. Evidence Binding:
   - Pass evidence items as compact tuples `(id, type, value, significance, confidence)` and require explicit referencing `[EVID: id]` inside narrative.
4. Calibration Frame:
   - Include guidance table: "Confidence thresholds: Certain ≥0.85, Likely ≥0.65, Plausible ≥0.45, Uncertain <0.45" and force classification.
5. Role Conditioning:
   - Provide personas: `Analyst`, `CISO`, `IR Lead`—generate micro-summaries per role.
6. Constraint Prompts:
   - Limit fluff words (list), require each task to start with a verb.
7. Hallucination Checks:
   - Post-pass: prompt model with generated summary + evidence list: "List any statements lacking direct evidence reference"; remove or annotate.

---
## 6. Data / Schema Enhancements to Support Better Output
Add fields upstream (prior pipeline or enrichment) so Tier 2 has richer context:
```jsonc
{
  "asset_criticality": "high|medium|low",           // host or system importance
  "data_sensitivity": "public|internal|restricted", // classification
  "control_gaps": ["EDR_missing", "DNS_logs_stale"],
  "exposure_window_hours": 42,                       // time to detection estimate
  "correlation_vector": {                            // from HopGraph or multi-session engine
    "user_overlap": 3,
    "host_overlap": 2,
    "process_chain_score": 0.74,
    "network_risk": 0.41
  },
  "detection_coverage": [                            // technique coverage status
    {"technique": "T1059", "name": "Command & Scripting", "coverage": "partial"}
  ],
  "incident_phase": "triage|containment|eradication|recovery"
}
```

---
## 7. Suggested New Structured Output Schema (Target)
```jsonc
{
  "summary": {
    "executive": {
      "headline": "string",                // distilled one-liner
      "impact": "string",                  // business impact
      "recommended_action": "string",      // imperative phrase
      "urgency_band": "critical|high|medium|low"
    },
    "key_judgments": [
      {"statement": "string", "confidence": 0.0, "evidence_refs": ["E1","E5"]}
    ],
    "evidence": {
      "items": [
        {"id": "E1", "type": "process", "value": "cmd.exe", "significance": "exec chain", "source": "EDR", "confidence": 0.82, "first_seen": "ISO8601"}
      ],
      "quality": {"corroborated": 6, "uncorroborated": 2, "gaps": ["no DNS logs"]}
    },
    "hypotheses": {
      "primary": {"description": "string", "confidence": 0.77},
      "alternatives": [
        {"description": "string", "confidence": 0.33, "discriminators": ["collect memory dump"], "status": "pending"}
      ]
    },
    "tasks": {
      "investigation": [
        {"id": "T1", "action": "Acquire memory image", "why": "Confirm credential theft", "owner": "IR", "priority": "high", "sla_hours": 4}
      ],
      "containment": [],
      "eradication": []
    },
    "timeline": {
      "events": [
        {"seq": 1, "timestamp": "ISO8601", "desc": "User login", "link_prev": null, "type": "auth"}
      ],
      "pivot_points": ["E3","E7"]
    },
    "intel": {
      "indicators": [
        {"value": "malicious.example", "type": "domain", "reputation": "high", "first_seen": "ISO8601"}
      ]
    },
    "coverage_gaps": ["No NetFlow", "No cloud audit logs"],
    "confidence_rationale": "string"
  },
  "meta": {
    "model": "llama3:8b",
    "cost_usd": 0.0152,
    "tokens_prompt": 1450,
    "tokens_completion": 2100,
    "cache_hit": false
  },
  "verification_report": {
    "evidence_coverage_pct": 78.5,
    "unsupported_statements": ["Claim about exfiltration"],
    "consistency_score": 0.83
  }
}
```

---
## 8. Backend / System Levers for Improvement
| Lever | Description | Action |
|-------|-------------|--------|
| Multi-Pass Summarization | Decompose into structured plan + fill phases | Add `/api/v1/csv/tier2_plan` endpoint returning JSON skeleton |
| Evidence Normalization | Standardize upstream pipeline evidence | Introduce normalization module before Tier 2 call |
| Verification Loop | Iterative claim-checking | Add `/api/v1/csv/tier2_verify` calling a lightweight cross-check prompt |
| HopGraph Correlation Injection | Enrich entity graph with centrality metrics | Extend graph session build to publish per-entity metrics into Tier 2 payload |
| Diversity & Mapping Weighting | Already enabled flags `include_mapping_semantics` | Provide numeric breakdown section in summary output |
| Adaptive Prompt Budgeting | Dynamically shorten sections if token pressure | Pre-calc token forecast; selectively compress evidence table |
| Persona-Specific Views | Different stakeholder slices | Add query param `audience=ciso|analyst|exec` to summary endpoint |
| Risk Framework Alignment | DREAD present; expand to CVSS/STRIDE mapping | Add crosswalk function to annotate each evidence item |
| Cost Tracking | Running total only shown | Add per-section cost attribution list |
| Replay / Drift Detection | Current cache age only | Compute semantic diff vs previous summary using embedding cosine |

---
## 9. Candidate Prompt Skeleton (Illustrative)
```
SYSTEM: You are producing a Tier 2 investigation summary. Output strictly in JSON matching the provided schema.
CONTEXT: {serialized_row_fragment}
DOMAIN_PROFILE: {domain} (confidence {confidence})
EVIDENCE_ITEMS: [{id,type,value,significance,source,first_seen,last_seen,confidence}]
INSTRUCTIONS:
1. Populate executive.headline (< 110 chars, no passive voice).
2. key_judgments: 3–6 statements; each must reference ≥1 evidence id.
3. hypotheses: include primary + 1–3 plausible alternatives with discriminators.
4. tasks: produce investigation tasks prioritized by urgency; each action starts with a strong verb.
5. timeline: order events; identify pivot_points.
6. coverage_gaps: list missing telemetry.
7. confidence_rationale: cite evidence density, corroboration, gaps.
OUTPUT_JSON_SCHEMA: {...}
```
Follow with second refinement prompt: "Refine summary: remove redundancy, ensure tasks uniquely advance hypothesis discrimination or containment. Return only updated JSON.".

---
## 10. Frontend Enhancements
- Collapsible structured sections with copy buttons per block.
- Role tabs (Analyst / CISO / Ops) switching JSON slices.
- Heat-map styling for confidence values.
- Task board conversion: drag-and-drop tasks classified by phase.
- Quick export: Markdown and SOC ticket template.
- Inline verification diff: highlight removed unsupported statements.

---
## 11. Files Recommended for Claude Review (Context Breadth)
| File | Why It Matters |
|------|----------------|
| `frontend/static/csv_deep_analysis.html` | Core UI & current DOM/data binding logic. |
| `frontend/static/csv_analyzer.html` | Upstream data acquisition & row selection context. |
| `src/api/graph_session_endpoints.py` | Correlation factors; potential to enrich Tier 2 with multi-source overlaps. |
| `src/core/graph/hopgraph_lite.py` | Graph capabilities, metrics for centrality or correlation injection. |
| `src/api/hopgraph_persistence.py` | Snapshot/restoration semantics; could inform continuity of investigations. |
| `tests/test_hopgraph_lite.py` | Reveals assumptions about reconstruction & temporal queries (can inform evidence timeline derivation). |
| `src/api/assessments/*` (if present) | LLM verification endpoints & semantics around assessment objects. |
| `src/security/auth.py` | Understanding gating for possible new endpoints (tier2_plan, tier2_verify). |

Optional (if model can handle more): `graph_session_endpoints.py` (both versions in file), and any file providing MITRE or factor tagging logic.

---
## 12. Roadmap Phasing
| Phase | Milestone | Deliverable |
|-------|-----------|------------|
| 1 | Structured Schema & Two-Pass Generation | New endpoints + schema validation tests |
| 2 | Evidence Normalization & Verification | Evidence score & unsupported claim filter |
| 3 | HopGraph Enrichment | Centrality metrics, mapping/diversity weight breakdown |
| 4 | Persona Views & Task Board | Frontend enhancements, role toggles |
| 5 | Calibration & Cost Attribution | Confidence mapping + per-section cost telemetry |
| 6 | Drift Detection & Cache Intelligence | Semantic diffing; freshness indicator |

---
## 13. Validation & Metrics
- Coverage Ratio: (# evidence items referenced in key_judgments) / total evidence items.
- Actionability Index: % tasks with explicit `why` + `owner` + `sla_hours`.
- Redundancy Score: Jaccard similarity between judgment sentences after lemmatization (target < 0.25 overlap average).
- Hallucination Rate: Unsupported statements / total statements (target → <5%).
- Confidence Calibration: Ex-post alignment of predicted confidence vs. empirical verification pass outcome.

---
## 14. Minimal Implementation Steps (Backend)
1. Define `Tier2PlanSchema` / `Tier2SummarySchema` pydantic models.
2. Implement `/api/v1/csv/tier2_plan` (returns skeleton + evidence tagging suggestions).
3. Implement `/api/v1/csv/tier2_summarize` (consumes plan + evidence, returns structured JSON).
4. Add `/api/v1/csv/tier2_verify` (hallucination & coverage checks).
5. Integrate HopGraph enrichment (optional param `include_graph_metrics`).
6. Add tests: schema validation, hallucination detection with synthetic evidence, caching semantics.

---
## 15. Risks & Mitigations
| Risk | Mitigation |
|------|------------|
| Increased token cost | Two-phase approach reduces regeneration scope; layer caching.
| Schema Drift | Version fields (`schema_version`) + strict pydantic validation.
| Hallucination Persistence | Verification loop auto-strips unreferenced sentences.
| Analyst Overload | Provide toggle for advanced fields; default minimal view.
| Confidence Misuse | Display band + rationale; link to calibration doc.

---
## 16. Quick Reference (What to Share with Claude)
Provide:
1. This document.
2. Raw HTML file `csv_deep_analysis.html`.
3. `graph_session_endpoints.py` (for correlation semantics).
4. Proposed target schema (Section 7 JSON).
5. Evidence normalization needs (Section 6).
6. Prompt skeleton (Section 9).

Ask Claude to:
- Highlight ambiguities.
- Suggest reduction strategies for token usage while increasing actionability.
- Provide refined schema with optional extension fields for IR automation (e.g., STIX mapping).

---
## 17. Next Actions (Immediate)
- [ ] Add backend pydantic models.
- [ ] Prototype `/tier2_plan` endpoint.
- [ ] Implement two-pass summarization with a cheap model for plan, richer model for expansion.
- [ ] Add verification endpoint & UI diff view.

*End of document.*
