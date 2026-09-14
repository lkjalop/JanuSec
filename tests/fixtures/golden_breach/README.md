# Golden breach corpus v1

This small deterministic corpus is the acceptance seed for the AssessmentRun
DAG. It is deliberately simple enough to inspect by hand. It tests evidence
integrity and epistemic behavior, not model cleverness.

- `breach.jsonl`: positive identity → endpoint → cloud sequence.
- `benign.jsonl`: same user with normal successful activity; must not be promoted
  to a breach claim merely because identifiers overlap.
- `missing_sensor.jsonl`: the endpoint event is absent; expected result is an EDR
  coverage gap, not a synthetic bridge.
- `delayed_log.jsonl`: cloud valid time precedes its known time by 19 minutes.
- `cross_tenant.jsonl`: a lookalike identity/IP belongs to another tenant and must
  never participate in the first tenant's graph or retrieval pack.

`manifest.json` contains the invariants. Future larger fixtures can extend this
case without changing its semantic IDs.
