# 15. Artifact Intelligence Sidecar Integration Guide
Status: Draft
Last Updated: 2025-09-23
Related: `14-frontend-console-spec.md`, backend API modules

---
## 1. Overview
The Artifact Intelligence Sidecar provides a pluggable enrichment, clustering, and risk synthesis layer for file / script / macro inventories originating from endpoints, EDR/XDR platforms, or bulk offline exports. It produces:
- Per-artifact risk score & verdict (0–100 scaled buckets)
- Factorized explainability (weighted contribution breakdown)
- MITRE / STRIDE coverage hints & deltas
- Rarity & prevalence classification (rare / emerging / common)
- Semantic clustering (embedding + online centroid)
- Business impact narrative & recommended actions (conditional)
- Propagation & multi-host spread detection
- Reputation & post-VT enrichment with risk recalculation
- Analyst override support & persistence

---
## 2. Core Feature List
| Category | Feature | Description | Value |
|----------|---------|-------------|-------|
| Ingestion | Multi-format upload | CSV / XLSX / JSONL / ZIP container | Low friction integration |
| Normalization | Field mapping & type inference | Derives artifact_type via path/extension | Reduces upstream strictness |
| Factor Taxonomy | Static / Macro / Script / Origin / Persistence / Relational / Temporal / Reputation / Rarity | Weighted contributions | Explainable scoring |
| Clustering | Embedding + threshold centroid grouping | Lightweight semantic grouping | Detect variant families |
| Rarity | Prevalence persistence across batches | Rare vs emerging vs common | Prioritization |
| Propagation | Multi-host correlation tracking | Spread factor raises risk | Early lateral detection |
| Mapping | MITRE/STRIDE/CVE hints | Factor → technique lookup | Executive coverage framing |
| Risk Synthesis | Weight aggregation + gating | Deterministic base + optional LLM delta (capped) | Consistency & adaptivity |
| Ambiguity Gating | Band-based LLM invocation | Only refine when uncertain | Cost & noise control |
| Reputation | Async VirusTotal queue | Post-pass risk adjustments | External confirmation |
| Reporting | JSON + Markdown + business summary | Export & share | Stakeholder alignment |
| Overrides | Analyst feedback persistence | Adjust verdict + rationale | Human judgment inclusion |
| Metrics | Factor counts, risk distribution, rarity, ambiguity, adjustments | Internal observability | Tuning & QA |
| Distribution | Slack webhook alerts | High-risk / rare / propagation notifications | Fast SOC awareness |
| Calibration | Prevalence stability test harness | Multi-batch variation analysis | Trust building |

---
## 3. Supported Artifact Types & Detection Targets
| Artifact Type | Examples | Heuristics / Factors Emphasized |
|---------------|----------|----------------------------------|
| EXECUTABLE | .exe, .dll, ELF | Signature, origin path, propagation, rarity, reputation |
| SCRIPT | .ps1, .vbs, .js, .sh | Obfuscation, spawn chains, macro-lateral bridging |
| MACRO | .docm, .dotm, .xlsm | AutoExec detection, embedded strings, download recency |
| DOWNLOAD | Recent items in Downloads/Temp | Age, rarity, signedness |
| LIBRARY | .dll, .so | Injected load patterns (future), signature |
| SERVICE / PERSISTENCE | Run keys, startup items (future) | Persistence factor weighting |

---
## 4. Input Data Contracts
Minimum Required Per Artifact Record:
- `artifact_name`
- `path` OR `hash_sha256`
Optional (improves quality): `artifact_type`, `host_id`, `user`, `signed`, `size_bytes`, `download_url`, `first_seen`, `cluster_hint`

Accepted Bulk Formats:
- CSV (UTF-8 header required)
- XLSX (first sheet; multi-sheet selection planned)
- JSONL (one artifact JSON per line)
- ZIP (containing any above; flattened)

Rejected / Sanitized:
- HTML, binary blobs, executables (for security in web upload context)

---
## 5. Output Objects (Simplified)
```jsonc
{
  "batch_id": "BATCH-2025-09-23-001",
  "status": "COMPLETE",
  "artifacts": [
    {
      "id": "a_macro_payload_dotm",
      "artifact_name": "macro_payload.dotm",
      "artifact_type": "MACRO",
      "risk_score": 72,
      "verdict": "HIGH",
      "rarity": "EMERGING",
      "hosts": 1,
      "cluster_id": "7",
      "factors": [{"category":"MACRO","score_delta":20,"label":"Embedded AutoExec Macro"}],
      "mitre": ["T1566","T1204"],
      "stride": ["Repudiation"],
      "reputation": {"vt_detect":14,"vt_total":62},
      "prevalence": {"first_seen":"2025-09-23T14:15:00Z","historical_count":1}
    }
  ],
  "mitre_coverage": ["T1059","T1105","T1566","T1204"],
  "mitre_delta": ["T1566","T1204"],
  "business_impact": {"summary":"Potential macro-based foothold"}
}
```

---
## 6. Risk Model Summary
- Deterministic Weighted Sum across factor categories.
- LLM Adjustment (optional) only if risk within ambiguity band + JSON schema validated + delta capped (e.g., ±5 absolute).
- Rarity & Propagation act as multiplicative or additive modifiers (implementation: additive deltas with category gating).
- Post-VT Enrichment: reputation factors re-run; risk recalculated; metrics track delta.

Verdict Buckets:
- BENIGN (0–19)
- LOW (20–44)
- SUSPICIOUS (45–64)
- HIGH (65–79)
- MALICIOUS (80–100)

---
## 7. Prevalence & Rarity Mechanics
- State persisted in `artifact_prevalence.json` (host + artifact identifier counts).
- Rare: first appearance.
- Emerging: < =2 historical occurrences & limited spread.
- Common: beyond threshold and stable across ≥3 batches.
- Multi-Host Spread Factor triggers when host set cardinality > threshold (default >3).

---
## 8. Clustering Strategy
- Embedding provider: sentence-transformers (or deterministic fallback hash) → vector.
- Online centroid manager: assign to existing cluster if cosine similarity ≥ threshold (e.g., 0.86); else create new.
- Cluster metadata: size, representative name, risk centroid (average), technique union.
- Use Case: identify families / variant drift; accelerate triage by group.

---
## 9. Integration Patterns (High-Level)
| Pattern | Direction | Method | Notes |
|---------|-----------|--------|-------|
| Direct Upload UI | Ingestion | Browser POST → REST | Human-driven / ad hoc |
| API Batch Submit | Ingestion | `POST /api/artifacts/batch_analyze` | Automated pipelines |
| Scheduled Offline Runner | Ingestion | CLI script + cron | Air-gapped or bulk backfill |
| Slack Webhook Alerts | Egress | Slack Incoming Webhook | High-risk & rarity notifications |
| Markdown Export | Egress | Download / Email (future) | Exec sharing |
| JSON Report Pull | Egress | `GET /api/artifacts/report/latest` | Dashboard embedding |
| Webhook Push (Future) | Egress | Outbound HTTP POST | Integrate with ticketing / SIEM |

---
## 10. Eclipse XDR Integration (Conceptual)
### 10.1 Ingestion from Eclipse XDR → Sidecar
1. Export Endpoint Inventory Feed (scheduled) containing file/process listings (CSV/JSONL).
2. Normalize fields to sidecar schema (mapping table below).
3. POST aggregated artifacts to `/api/artifacts/batch_analyze` (optionally chunk if very large).
4. Poll or wait for completion; store batch_id for correlation.

Field Mapping Table:
| Eclipse Field | Sidecar Field | Notes |
|---------------|--------------|-------|
| process_name / file_name | artifact_name | Required |
| file_path | path | At least one of path/hash required |
| sha256 | hash_sha256 | Prefer cryptographic hash |
| signed_status | signed | Boolean/enum mapping |
| first_seen_timestamp | first_seen | ISO-8601 required |
| host_identifier | host_id | FQDN or asset ID |
| user_context | user | Optional |

### 10.2 Egress from Sidecar → Eclipse XDR
Approaches:
- Periodic Pull: Eclipse queries sidecar `GET /api/artifacts/report/latest` and merges verdicts into its enrichment pipeline.
- Webhook Push (Future): Sidecar sends POST to Eclipse ingestion endpoint with high-risk artifact JSON.
- Slack to XDR Relay (Interim): Slack alert includes deep link referencing artifact_id for pivoting.

Sample Egress Payload (POST):
```json
{
  "integration": "artifact_sidecar",
  "batch_id": "BATCH-2025-09-23-001",
  "artifacts": [
    {"artifact_name":"powerscan.exe","hash_sha256":"...","risk_score":87,"verdict":"MALICIOUS","techniques":["T1059","T1105"],"hosts":4}
  ],
  "generated_at": "2025-09-23T14:32:00Z"
}
```

---
## 11. API Usage Examples
Upload (JSON, after client conversion):
```bash
curl -X POST https://sidecar/api/artifacts/batch_analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @batch_payload.json
```

Fetch Report:
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  https://sidecar/api/artifacts/report/latest?batch_id=BATCH-2025-09-23-001
```

Override:
```bash
curl -X POST https://sidecar/api/artifacts/feedback \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"artifact_id":"a_powerscan_exe","override_verdict":"BENIGN","rationale":"Known IT tool variant"}'
```

Slack Webhook Test Setup (server side env): `ARTIFACT_SLACK_WEBHOOK=https://hooks.slack.com/services/...`

---
## 12. Environment & Configuration Variables
| Variable | Purpose | Example |
|----------|---------|---------|
| `ARTIFACT_REPUTATION_ENABLED` | Toggle VT queue | true |
| `VT_API_KEY` | VirusTotal key | (secret) |
| `ARTIFACT_SLACK_WEBHOOK` | Slack alerts | https://hooks.slack.com/... |
| `ARTIFACT_LLM_PROVIDER` | Optional LLM name | openai:gpt-4o-mini |
| `ARTIFACT_LLM_MAX_DELTA` | Cap risk delta | 5 |
| `ARTIFACT_CLUSTER_THRESHOLD` | Cosine similarity threshold | 0.86 |
| `ARTIFACT_MULTI_HOST_THRESHOLD` | Multi-host spread trigger | 3 |
| `ARTIFACT_RARE_MAX_HISTORY` | History windows to consider rare | 0 |

---
## 13. Deployment Models
| Model | Description | Pros | Cons |
|-------|-------------|------|------|
| Sidecar API Service | Standalone container w/ REST endpoints | Clear separation | Requires network route |
| Embedded Library | Linked inside existing XDR ingestion worker | Lower latency | Tight coupling updates |
| Hybrid | Library + remote clustering service | Scalability | Complexity |

MVP Recommendation: Sidecar API Service container + token auth.

---
## 14. Operational Metrics (Suggested)
| Metric | Description |
|--------|-------------|
| `artifact_batches_total` | Count processed batches |
| `artifact_risk_histogram` | Distribution of risk buckets |
| `artifact_rare_count` | Rare artifacts per batch |
| `artifact_llm_invocations_total` | LLM refine calls |
| `artifact_post_vt_adjustments_total` | Count risk recalculations after VT |
| `artifact_cluster_count` | Current cluster cardinality |

---
## 15. Security & Hardening
- HMAC signature validation for automated ingestion (optional header `X-Sidecar-Signature`).
- Strict JSON schema validation (reject unknown top-level keys optionally).
- Rate limiting (batch submit) per token.
- Sanitize all text fields (avoid HTML injection in UI).
- Encryption at rest for persistence store (if containing host IDs sensitive).

---
## 16. Failure & Retry Semantics
| Stage | Failure Mode | Recovery |
|-------|--------------|----------|
| Upload | Invalid schema | 400 + error list |
| Clustering | Embedding model unavailable | Fallback to deterministic hashing cluster strategy |
| Reputation | VT quota exceeded | Queue retry w/ backoff; mark interim as pending |
| LLM | Timeout / parse error | Skip refinement; record metric; continue deterministic risk |
| Persistence | File write fail | Log & buffer in memory; alert if >N retries |

---
## 17. Integration Quick Start (Script Assisted)
1. Export endpoint inventory from Eclipse XDR to CSV (fields: file_name, path, sha256, host_identifier, signed_status, first_seen_timestamp).
2. Run `python scripts/excel_batch_analyze.py --input exported.csv --api https://sidecar/api --token $TOKEN`.
3. Poll until batch status COMPLETE -> store JSON for correlation.
4. Configure `ARTIFACT_SLACK_WEBHOOK` for real-time alerts.
5. (Optional) Schedule daily prevalence calibration.

---
## 18. Roadmap Hooks
- Email digest scheduling (/digest endpoint)
- Outbound webhook push for high-risk events
- Enhanced behavioral correlation (sandbox) factor category
- Role-based override workflow approvals

---
## 19. Acceptance Checklist
- [ ] Ingestion field mapping tested against Eclipse export sample
- [ ] Slack alert test delivered
- [ ] Override persistence verified
- [ ] Prevalence state persists across two sequential batches
- [ ] Cluster formation threshold validated (>= one multi-member cluster)

---
End of Guide
