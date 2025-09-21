# Module Contracts

## Common Conventions
- All modules expose: `init(config)`, `check_health()`, and their primary method (`process(event)` or stage-specific name).
- Return either a partial `Decision` (fields filled) or an `Enrichment` object consumed downstream.
- Errors must never raise uncaught exceptions past orchestrator; they yield safe fallback objects.

## BaselineModule
Purpose: Deterministic filtering & cheap confidence seeding.
Input: NormalizedEvent
Output: `BaselineResult {confidence: float, factors: [string], terminal: bool, disposition?: string}`
Logic: Indicator / allowlist / frequency heuristics; no external blocking network calls.
Budget: <1ms p95

## IntelligentRouter
Purpose: Decide path based on confidence & heuristic risk weight.
Input: BaselineResult + Event
Output: RoutingDecision {path: benign|malicious|deep, reason}

## NetworkThreatHunter
Purpose: Add network behavioral factors (geo risk, ASN rep deltas, unusual port mix, connection cardinality).
Input: Event + sliding network state
Output: Enrichment {factors: [string], partial_confidence_delta: float}
State: ring buffers keyed by src/dst, recent distinct counts.

## EndpointHunter
Purpose: Host behavior (process lineage anomalies, persistence artifacts).
Input: Event + endpoint state cache
Output: Enrichment {factors, partial_confidence_delta}

## MalwareAnalyzer (Deferred Phase)
Purpose: Controlled dynamic/static analysis when file indicators unresolved.
Trigger: factor `file_unclassified` + suspicious cluster membership.

## ComplianceMapper
Purpose: Map factors → frameworks (MITRE, STRIDE, control sets) & compute impact vector.
Input: Decision snapshot (factors, confidence)
Output: Enrichment {impact_vector, mappings, compliance_controls}

## GovernanceModule
Purpose: Policy enforcement (deny actions, approval gating) + audit augmentation.
Input: Decision pre-finalization
Output: Possibly modified decision + appended factors (e.g. `requires_approval`).

## HardeningModule
Purpose: Platform self-protection (rate limiting, payload sanitization, signature checks).
Input: Raw or NormalizedEvent
Output: Possibly dropped or sanitized event.

## PlaybookExecutor
Purpose: Deterministic response action runner with idempotency & rollback notes.
Input: Final Decision (malicious & authorized)
Output: ExecutionReport {actions_attempted, successes, failures}

## MetricsExporter
Purpose: Single ingestion point for metrics emission; ensures consistent labels.
Interface: `record(metric_name, **labels)`; internal aggregation uses counters/histograms.

## StorageManager
Purpose: Unified CRUD abstraction (hot, warm, cold tiers) with custody hashing.
Interface: `store_event`, `promote_event`, `archive_event`, `verify_hash(event_id)`.

## NLPIntentEngine (Deferred until after core stability)
Purpose: Translate analyst natural language to structured query plan.
Output: QueryPlan {intent, filters, time_range}
Fallback: If intent confidence < threshold, request clarification.

## Confidence Model Adjustments
Each enrichment module MAY contribute a bounded delta to confidence: `delta ∈ [-0.15, +0.20]` to prevent runaway escalation.

## Decision Finalization
Criteria: (disposition determined) OR (max stages reached) OR (confidence outside routing band after deep stage N) OR (timeout budget exceeded).

## Timeout Budgets
| Stage | Budget (ms) | Strategy on Timeout |
|-------|-------------|----------------------|
| Baseline | 1 | Mark `baseline_timeout`, continue w/ neutral confidence |
| NetworkHunter | 10 | Add factor `network_partial` |
| EndpointHunter | 15 | Skip malware stage |
| MalwareAnalyzer | 200 (async) | Defer result; attach later via update channel |
| ComplianceMapper | 5 | Proceed without mappings |

## Error Handling Codes (Factors)
| Condition | Factor |
|-----------|--------|
| TI cache unreachable | `ti_unavailable` |
| Redis unavailable | `hot_tier_degraded` |
| Policy eval error | `policy_eval_error` |
| Storage hash mismatch | `custody_verification_failed` |

## Extensibility Hooks
- Pre-routing hook: last chance to inject global suppression factors.
- Post-enrichment hook: modify or redact factors based on policy.
- Pre-finalization hook: sign decision with config digests.

## Minimal Data Schemas
```
NormalizedEvent {
  id, ts, src_ip, dst_ip, user?, host?, domain?, file_hash?, process_name?, raw:{...}
}
Enrichment {factors:[string], partial_confidence_delta?: float, metadata?: dict}
ImpactVector {confidentiality, integrity, availability, propagation}
```
