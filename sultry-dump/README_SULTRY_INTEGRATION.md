# Sultry.ai Modular Correlation Extraction (From JanuSec)

This folder contains curated, de‑scoped source excerpts from the JanuSec platform to accelerate Sultry.ai's Modular Correlation Engine. Each file selected here focuses on:

1. Factor Extraction & Normalization
2. Risk Synthesis & Verdict Mapping
3. Lightweight HopGraph (context / relationship memory)
4. Threat Modeling Mappings (MITRE / STRIDE / PASTA hooks / DREAD scoring inputs)
5. Compliance & Control Mapping (minimal scaffolds)

> Guiding Principle: Import only the domain logic (pure / minimal side‑effects) and avoid deployment, heavy framework, or persistence tangles. Treat these as design patterns or starting templates — not drop‑in production code.

---
## File Index & Adaptation Guidance

| New Path | Origin (JanuSec) | Purpose | Sultry Adaptation Notes |
|----------|------------------|---------|-------------------------|
| `artifact_factors.py` | `src/artifact/factors.py` | Canonical factor taxonomy + extraction heuristics & weights | Externalize weights to dynamic policy store (e.g. feature flags or DB); convert constants to declarative YAML/JSON for rapid tuning; instrument extraction with telemetry events. |
| `artifact_risk.py` | `src/artifact/risk.py` | Component aggregation & synergy heuristic risk adjustments | Replace hardcoded synergy with rule graph or learned model; expose pluggable post-process hooks (LLM, ensemble). |
| `artifact_models.py` | `src/artifact/models.py` | Data structures: artifact observation, verdict mapping, factor categories | Convert to Pydantic / dataclasses with version field; add schema evolution & JSON schema export. |
| `hopgraph_lite.py` | `src/core/graph/hopgraph_lite.py` (trim) | Sliding window relationship memory (user-host-proc-net) for contextual factors | Abstract storage (strategy pattern) so in-memory, Redis, or streaming backends swap; add feature: time-partitioned shards + adaptive pruning metrics. |
| `mitre_stride_framework_catalog.py` | `src/mapping/framework_catalog.py` | Sample mapping factor→framework meta (MITRE, STRIDE) | Normalize into unified `frameworks.json`; include support for PASTA stage + control families, produce coverage matrices. |
| `dread_scorer_stub.md` | (concept from `src/analysis/dread_scorer.py` & usage sites) | Documents integration of DREAD scoring inputs | Implement scoring as weighted function with override pipeline; enable A/B testing of scoring formulas. |
| `compliance_mapper_stub.md` | `src/modules/compliance_mapper.py` (+ related compliance package) | High-level approach for compliance evidence & logical gates | Rebuild using domain-driven aggregates: Control, Evidence, Assertion; connect to factor outputs for control coverage analytics. |

---
## Conversion Checklist

### 1. Factor System
- Extract weight table -> `factors.weights.json` (suggested new artifact) for dynamic reload.
- Introduce weight provenance metadata: `{source: 'baseline' | 'experiment' | 'ml_adjust', last_updated, author}`.
- Add feature importance logging (serialize frequency & contribution deltas for offline tuning).

### 2. Risk Synthesis
- Replace hardcoded `COMP_WEIGHTS` with hierarchical config: component group -> weight -> cap.
- Add optional ML risk blender: `final_risk = alpha*heuristic + (1-alpha)*model_pred` with adaptive alpha based on confidence dispersion.
- Export intermediate vector: `[static_score, origin_score, behavior_score, relational_score, reputation_score, synergy_flags...]` for model training.

### 3. HopGraph Evolution
- Current: ephemeral deque + edge timestamp GC.
- Add: streaming ingestion adapter (Kafka/NATS) writing normalized edges; snapshot compactor job.
- Introduce context queries API spec: `get_context(entity_id, horizon, feature_set)` returning structured features.
- Add rarity baselining: maintain approximate count-min sketches per name/process to classify RARE/EMERGING.

### 4. Threat Modeling Integration
- Unify MITRE / STRIDE / PASTA via a `ThreatDimension` enum; mapping entries become multi-dimensional descriptors.
- Provide coverage service generating: technique coverage %, stride balance, pasta stage distribution → feed dashboards & gap analysis.
- Add mapping confidence attribute (low/medium/high) for heuristic vs deterministic associations.

### 5. DREAD & Multi-Scoring
- Encapsulate DREAD as plug: `score(context: ArtifactObservation) -> DreadResult`.
- Maintain parallel scoring tracks (DREAD / FAIR-like) stored under `observation.scores['dread']` etc.
- Provide score explanation graph (factor -> component -> overall) for transparency.

### 6. Compliance Correlation
- Link factor categories to control objectives: e.g., `unsigned_binary` → AppSec / Code Integrity.
- Generate `controls_coverage.json` summarizing observed factors mapped against a control library (NIST, CIS).

### 7. Extensibility Hooks
- Pre-Extraction Middleware (normalize inputs, enrich with asset inventory).
- Post-Extraction Middleware (LLM reasoning, sandbox enrichment, risk diffing).
- Factor Override Layer (apply manual analyst boosts / suppressions with auditable trail).

---
## Inclusion Decisions: What & Why

| Domain | Included? | Rationale |
|--------|-----------|-----------|
| Factor extraction logic | Yes | Core deterministic signal generation foundation. |
| Risk synthesis heuristics | Yes | Baseline scoring to backfill while ML models train. |
| HopGraph lite core | Partial | Lightweight contextual memory blueprint without heavy persistence. |
| Full API / routers | No | Framework-specific & out-of-scope for modular engine. |
| Heavy integrations (sandbox, threat intel) | No (reference only) | Replace with Sultry plugin interfaces. |
| Compliance runtime code | Stub only | Provide conceptual mapping path, avoid coupling. |
| Enrichment frameworks (full) | Partial (catalog) | Enough to map factors → frameworks for coverage. |

---
## Threat Modeling Factors Scope
Yes — recommend including MITRE, STRIDE, PASTA stage placeholders, DREAD, and compliance control linkage. Unify via internal canonical factor taxonomy; store relationships in `threat_dimensions.json` (factor -> {mitre:[...], stride:[...], pasta_stage, controls:[...] }).

### Suggested JSON Structure
```json
{
  "lolbin_misuse": {"mitre": ["T1218"], "stride": ["Defense Evasion"], "pasta_stage": 5, "controls": ["AppWhitelisting", "ExecutionPolicy"], "confidence": "high"},
  "fresh_download": {"mitre": ["T1105"], "stride": ["Tampering"], "pasta_stage": 3, "controls": ["SecureGateway"], "confidence": "medium"}
}
```

---
## HopGraph Export Strategy
- Minimal interface: `observe(event)`, `context(artifact)`, `flush()`.
- Add feature extraction layer producing: rarity, burst score, multi-host emergence, malicious_neighbor density.
- Optionally expose gRPC/REST microservice for horizontally scalable context queries.

---
## Integration Sequencing for Sultry.ai
1. Port data classes (`artifact_models.py`) → adapt naming to Sultry domain.
2. Externalize weight & mapping configs (factors, frameworks, dimensions).
3. Implement factor extraction pipeline with instrumentation.
4. Drop in risk synthesis; wrap with adapter to produce normalized `CorrelationResult` object.
5. Integrate HopGraph-lite (or existing graph store) for contextual factor injection.
6. Add threat dimension mapping + coverage metrics.
7. Layer in DREAD / alternative scoring methods.
8. Build compliance coverage translator (controls <- factors).
9. Introduce ML blending & adaptive weights once telemetry baseline stable.

---
## License & Attribution
Retain original notices if any (none copied here beyond logic) and clearly mark adapted code as derivative in Sultry.ai internal docs. Ensure proprietary / sensitive integration endpoints are excluded.

---
## Next Steps (Actionable)
- [ ] Extract factor weights to JSON & add reload mechanism.
- [ ] Implement ThreatDimension registry loader.
- [ ] Add metrics: extraction_latency_histogram, risk_component_distribution, factor_frequency.
- [ ] Build coverage dashboard summarizing technique / stride / control ratios.
- [ ] Add AB test harness for alternative COMP_WEIGHTS sets.

