# Hunt Lanes Phase 1 (Advisory Mode)

## Objectives
Provide high-signal endpoint & network behavioral heuristics (Process Lineage + JA3 Novelty) inside an **Evidence Envelope** abstraction without prematurely increasing confidence / verdict risk. Capture telemetry (latency, counts, distinct baseline sizes) to evaluate entropy, precision uplift and false positive suppression before enabling scoring influence.

## Components
- EvidenceEnvelope: Immutable wrapper carrying event + lane emissions.
- LaneRegistry: Executes registered lanes if `pipeline.hunt_lanes.enabled` is true. Per-lane toggles supported under `pipeline.hunt_lanes.lanes.<lane>=bool`.
- Lanes Implemented:
  - process_lineage: parent/child combinations, encoded PowerShell, orphan process, signed→unsigned transition.
  - ja3_novelty: novelty/rarity of TLS JA3 hashes (warm-up baseline).
- Persistence: `hunt_lane_events` table (lane, factors[], latency_ms) for replay analytics.
- Metrics:
  - `hunt_lane_latency_ms{lane}` histogram
  - `hunt_lane_events_total{lane}` counter
  - `ja3_baseline_size`, `ja3_distinct_hashes` gauges

## Advisory vs Confidence Mode
| Mode | Description | Activation Criteria | Risks | Mitigations |
|------|-------------|---------------------|-------|-------------|
| Advisory (current) | Factors emitted prefixed `lane_<lane>:`; zero confidence delta | Default at deploy | None to verdict | Collect precision & entropy first |
| Confidence Enabled (future) | Lane factors contribute bounded deltas (caps) | After replay + real traffic analysis demonstrates uplift | Potential FP inflation if heuristics noisy | Factor quality suppression + per-lane weight caps + feedback decay |

## Toggle Strategy
Always-on by default but with advisory-only effect ensures continuous telemetry. A kill-switch `pipeline.hunt_lanes.enabled=false` disables all lane execution instantly (low risk). Per-lane toggles allow isolating a noisy lane without losing others.

Trade-off:
- Always-on (advisory) yields richer historical data for calibration; minimal CPU overhead (~ microseconds per lane) vs complexity of retroactive enable toggles producing cold-start blind spots.
- Fully toggleable lane off by default delays baseline formation; novelty detection (JA3) needs warm baseline to reduce false spikes.

Decision: **Enable lanes in advisory from day one**; rely on per-lane toggle only for containment of discovered regressions.

## Governance & Error Taxonomy Integration
- Lane emissions are namespaced: `lane_<lane>:<factor>` ensuring downstream quality suppression, mapping, and auditing treat them distinctly.
- Errors inside a lane are caught and logged as warnings; no pipeline failure propagation (taxonomy: `lane_error/<lane>` could be added if we later want metrics).
- Factor Quality Layer: Because lane factors arrive before suppression, existing FP ratio suppression will automatically mute persistently noisy lane signals post-promotion.

## Adaptive Tuner Interplay
Adaptive tuner currently receives cumulative factors pre-lane. In Phase 2 we can optionally provide lane entropy & precision stats to tuner for dynamic weighting simulation. The envelope design isolates this evolution.

## Prometheus & Grafana Impact
New metrics allow dashboards:
- Lane latency distribution vs core stages.
- Lane emission rates vs total events (signal sparsity).
- JA3 baseline growth (stabilization curve) to determine when novelty detection is reliable.
- Correlation (future) rule hit counts; measure compounded context uplift.

## API Surfaces Added
- `GET /api/v1/hunt/lanes/status` lists registered lanes & enablement.
- `GET /api/v1/hunt/lanes/events?lane=<name>` returns recent persisted emissions.

## Analyst Value / FP Reduction Mechanics
1. Process lineage heuristics shrink investigation time by surfacing rare parent→child transitions & encoded script execution earlier (contextual triage classification).
2. JA3 novelty isolates previously unseen TLS clients (often early malware staging) without relying on full domain reputation—low-noise when warmed.
3. Advisory separation avoids premature alert fatigue; analysts can correlate lane factors with actual confirmed incidents before requesting scoring enablement.
4. Persistence + entropy tracking show diminishing returns (or value add) empirically; we only promote lanes that improve precision >= defined uplift threshold (e.g., +5% precision at constant recall).

## Roadmap Hooks
- Add `LOLBin lane` (catalog of living-off-the-land binary invocations with context weighting).
- Add `beacon_low_slow lane` (temporal jitter + low-bytes periodic connections).
- Introduce correlation rules: e.g., (process_lineage:office_macro_spawn_powershell + ja3_rare) => correlated factor `corr_office_ja3_chain`.
- Evaluate ML only after identifying residual gap (e.g., DNS DGA patterns not covered) measured via false negative sampling.

## Safety & Performance
- Execution time: lanes are lightweight string / dict lookups. Cap lane count to keep added latency < 2ms p95.
- Failure isolation: lane exception never aborts pipeline.
- Backward compatibility: If hunt lanes disabled, pipeline factors & metrics remain unchanged (idempotent integration).

## Key Trade-offs Summary
- Always-on advisory vs Opt-in: choose always-on to build baseline & trust early, minimal cost.
- Early ML vs Heuristic-first: retain heuristic-first to gain labeled evidence for targeted ML offering (cost efficiency & explainability).
- Monolithic vs Envelope Abstraction: envelope reduces future refactor cost when introducing evidence provenance groups & synergy engine.

## How This Lowers False Positives & Surfaces Malicious Behavior
- Adds discriminative context (e.g., rare JA3 + suspicious parent → high entropy compound) enabling more selective escalation later.
- Factor quality suppression ensures any noisy lane factor is auto-muted before scoring stage activation.
- Replay analysis quantifies lane factor conditional precision; only high conditional precision signals graduated to scoring, avoiding broad FP inflation.
- Encoded command & macro chain heuristics directly flag common initial access behaviors with historically high PPV (positive predictive value).

---
Phase 1 delivered: Envelope, Registry, Process Lineage, JA3 Novelty, Persistence, Metrics, API.
Next evaluation window: 3–5 days replay & live ingestion to compute lane factor entropy & conditional precision for promotion decisions.
