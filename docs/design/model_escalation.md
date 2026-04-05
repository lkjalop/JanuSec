# Model Escalation Engine Design

## Objective
Dynamically escalate analysis of ambiguous or high-impact artifacts/events through a multi-tier LLM/provider chain (local → small cloud → premium) to improve confidence while controlling cost and latency.

## Drivers
- Reduce spend by attempting cheapest adequate model first.
- Avoid blocking pipeline; escalate only when heuristic confidence < target window.
- Preserve transparency: record each tier attempt, incremental confidence gain, and final rationale.

## Scope (Phase 1)
- Synchronous best-effort escalation invoked after base factor synthesis but before final verdict persistence.
- Confidence augmentation only (no full content rewrite yet); output appended to `escalation_trace`.
- Per-item budget guard and global daily budget guard.

## Out-of-Scope (Phase 1)
- Asynchronous queue-based escalation.
- Multi-language summarization.
- Fine-tuned classification models (future replacement of heuristic gain function).

## Tier Chain Configuration
Environment variable: `MODEL_ESCALATION_CHAIN_JSON` example:
```json
[
  {"tier":0, "provider":"ollama",  "model":"llama3:8b",   "max_cost_units":0.05, "timeout_s":4},
  {"tier":1, "provider":"openai",  "model":"gpt-4o-mini", "max_cost_units":0.25, "timeout_s":6},
  {"tier":2, "provider":"anthropic","model":"claude-3-opus","max_cost_units":0.9, "timeout_s":8}
]
```
Fallback order = ascending `tier`.

## Trigger Heuristics
Escalation considered if ALL hold:
1. `base_risk` ∈ [escalate_threshold, block_threshold) OR contains catalyst factors (`rare_`, `corr_`, `multi_factor`, `lane_`).
2. `risk_confidence < CONF_MIN` (e.g. 0.55) OR `ambiguity > 0.4`.
3. Not already escalated in this batch.

## Stop Conditions
- Confidence meets or exceeds `CONF_TARGET` (e.g. 0.7) or max tier tried.
- Budget exceeded (per-item or cumulative daily).
- All tiers error/time out.

## Provider Adapter Interface
```python
class ModelProvider(Protocol):
    name: str
    async def generate(self, prompt: str, context: dict) -> ProviderResult:
        ...

@dataclass
class ProviderResult:
    text: str
    tokens: int
    cost_units: float
    latency_s: float
    error: str | None = None
```
Local adapter (Ollama) uses REST on `OLLAMA_BASE_URL`. Cloud providers keyed by API keys (OpenAI, Anthropic). HuggingFace option for local embedding/extractive summary.

## Confidence Gain Heuristic (Phase 1)
Basic function combining lexical cues:
```
Δconfidence = clamp( 0.08 * novelty_tokens + 0.05 * decisive_terms - 0.04 * hedge_terms, 0, 0.25 )
```
- `novelty_tokens`: count of artifact-specific tokens not in common baseline (normalized).
- `decisive_terms`: occurrences of terms like "confirmed", "malicious", "benign".
- `hedge_terms`: occurrences of "maybe", "unclear", "ambiguous".

Applied cumulatively but capped at `MAX_ESCALATION_GAIN` (e.g. 0.35) to avoid runaway inflation.

## Data Model Additions
Within each artifact observation record:
```json
"escalation_trace": [
  {
    "tier": 0,
    "provider": "ollama",
    "model": "llama3:8b",
    "confidence_gain": 0.11,
    "cost_units": 0.02,
    "latency_ms": 1320,
    "accepted": false,
    "error": null
  },
  {
    "tier": 1,
    "provider": "openai",
    "model": "gpt-4o-mini",
    "confidence_gain": 0.19,
    "cost_units": 0.14,
    "latency_ms": 980,
    "accepted": true
  }
],
"final_confidence": 0.72,
"escalation_status": "accepted"  # other values: none|partial|budget_exceeded|all_failed
```

## Cost Units
Abstract internal unit referencing approximate USD micro-cost so different providers normalize: cost_units = (input_tokens+output_tokens)/1k * provider_rate. Local models approximate GPU amortization.

## Pseudocode
```python
async def maybe_escalate(obs, base_conf, base_risk):
    if not triggers(obs, base_conf, base_risk):
        return base_conf, []
    chain = load_chain()
    trace = []
    cumulative_gain = 0.0
    for tier in chain:
        if budget_exceeded(): break
        res = await call_provider(tier, build_prompt(obs))
        gain = estimate_gain(res.text)
        gain = min(gain, MAX_ESCALATION_GAIN - cumulative_gain)
        new_conf = base_conf + cumulative_gain + gain
        trace.append({...})
        cumulative_gain += gain
        if new_conf >= CONF_TARGET: return new_conf, finalize(trace, accepted=True)
    status = derive_status(trace, cumulative_gain)
    return base_conf + cumulative_gain, finalize(trace, status=status)
```

## Failure Modes & Logging
- Provider error logged at WARN with provider name & artifact id hash.
- Timeout increments provider-specific failure counter (used for circuit breaker future).
- Trace entry includes `error` field instead of gain.

## Metrics (Prometheus plan)
- `model_escalation_attempts_total{provider}`
- `model_escalation_errors_total{provider}`
- `model_escalation_gain_sum` (summary or histogram)
- `model_escalation_latency_seconds_bucket{provider}`

## Security & Governance
- Redact secrets from trace.
- Cap per-artifact tokens (env: `ESCALATION_MAX_TOKENS=2048`).
- Optional allowlist of providers (env: `ESCALATION_ALLOWED_PROVIDERS=ollama,openai,anthropic`).

## Open Questions / Future
- Replace heuristic gain with calibrated logistic regression on provider response metadata.
- Feedback loop: analyst overrides adjust future trigger thresholds.
- Asynchronous expansion queue for large backlogs.

---
**Phase 1 Deliverable:** Engine scaffold, provider registry, heuristic gain estimator, integration hook in artifact pipeline, serialization of trace.
