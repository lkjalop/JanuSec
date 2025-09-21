# NLP Intent Specification (Lightweight)

## Goals
Enable natural-language style queries without large language models; deterministic + testable.

## Approach
1. Intent classification via ordered pattern match / small keyword automaton.
2. Entity extraction using regex & small lookup tables (techniques, factor names, subnet patterns).
3. Confidence scoring; if < threshold -> clarification prompt.

## Intents (Initial Set)
| Intent | Example | Output Plan |
|--------|---------|-------------|
| list_lateral_movement | "show lateral movement last 24h" | filter attack:T1021 timeframe=24h |
| list_novelty | "emerging behaviors this week" | novelty clusters timeframe=7d |
| list_exfiltration | "exfil events finance subnet" | factors includes data_exfil + subnet filter |
| list_failed_auth | "failed auth bursts yesterday" | auth failure anomaly factor timeframe=1d |
| summarize_risk | "risk summary for bu finance" | aggregate risk by business_unit |
| verify_custody | "verify event 123" | custody verify call |

## Entity Extraction Patterns
- Subnet: `(?P<subnet>\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b)`
- Technique: map token → technique id (dictionary from taxonomy)
- Time range: `(last|past)\s+(\d+)\s*(h|hours|d|days|w|weeks)`

## QueryPlan Structure
```
QueryPlan {
  intent: string,
  filters: {factors?: [string], subnet?: string, bu?: string},
  timeframe_s: int,
  confidence: float,
  raw: string
}
```

## Confidence Heuristics
- +0.4 if exact pattern match
- +0.2 if at least one recognized factor or technique
- +0.1 if time range parsed
- -0.3 if ambiguous overlap of multiple intent patterns

Thresholds: execute if ≥0.6 else request clarification.

## Clarification Strategy
Return suggestions: top 2 alternative intents with their key tokens.

## Testing
- Intent corpus: 50 sample queries; require ≥90% correct classification at ≥0.6 confidence.
- Fuzz tests: random token insertion -> ensure either low confidence or safe fallback.

## Open Questions
1. Add optional synonym config (CSV) for domain‑specific jargon? (Phase 2)
2. Support multi-intent chaining? (Defer; encourages complexity)
