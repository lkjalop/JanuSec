# Codebase Audit Plan

## Purpose
Provide a structured, repeatable deep-dive process to surface errors, drift, technical debt, security gaps, performance bottlenecks, and optimization opportunities while the codebase is still small enough for efficient remediation.

## Scope
In-scope directories: `src/`, `scripts/`, `tests/`, `config/`, `docs/` (governance), infra artifacts (`Dockerfile`, `docker-compose.yml`). Excludes vendored libs (`.venv/`).

## Audit Domains & Objectives
| Domain | Objective | Signals | Tools / Method | Exit Criteria |
|--------|-----------|---------|----------------|---------------|
| Dependency Health | Verify all required libs declared & minimal bloat | Missing imports, unused deps | Compare `requirements.txt` vs import graph | No unresolved imports; unused deps flagged |
| Static Correctness | Surface syntax/type issues early | Lint errors, type errors | `ruff` / `flake8`, (optional `mypy`) | Zero high-severity issues |
| Runtime Robustness | Identify fragile error handling & silent failures | Broad `except`, swallowed errors | Grep + manual inspection | Structured logging for all recoverable errors |
| Observability | Ensure metrics & logs sufficient | Missing latency metrics, missing tags | Inspect Prometheus metric coverage | All critical paths instrumented |
| Performance | Highlight hot paths & potential contention | Event loop blocking, sync I/O in async | Code scan for blocking calls | Blocking ops isolated or refactored |
| Security Controls | Validate authN/Z, tenant isolation, secret handling | Hardcoded secrets, lax ACL | Pattern scan; review `security/` | No plaintext secrets committed |
| Data Integrity | Guarantee custody & hash chain enforcement | Missing hash validations | Review chain logic | All persisted artifacts validated |
| Config & Feature Flags | Confirm toggles documented & safe defaults | Unused flags, default insecure | Search `config_manager` usage | All flags referenced & documented |
| Detection Fidelity | Check factor naming, governance prefixes | Inconsistent prefixes | Scan factors and lane emissions | 100% lane factors prefixed |
| Correlation Rules | Evaluate noise vs signal | Overlapping rules | Rule logic review | Rules have test coverage |
| Test Coverage Depth | Ensure critical modules tested | Missing tests for core logic | Map tests→modules | Coverage report > target |
| Docs & Runbooks | Confirm operational clarity | Stale references | Cross-check docs vs code | All key flows documented |
| Replay & Determinism | Ensure deterministic replays | Race conditions | Replay harness run | Replays produce stable outputs |

## Phased Approach
1. Baseline Collection (Automated)
2. Static Scan & Dependency Diff
3. Runtime Spot Checks (Targeted execution paths)
4. Deep Manual Review (High-risk modules)
5. Consolidated Findings & Risk Scoring
6. Remediation Sprint Planning
7. Post-Remediation Verification

## Tooling Recommendations
- Static: `ruff`, `mypy` (gradual), `bandit` (security heuristics)
- Dependency Graph: custom script using `ast` to extract imports
- Metrics Validation: curl `/metrics` endpoint, verify presence of expected families
- Replay Determinism: run `scripts/replay_harness.py` twice, diff outputs
- Drift Detection: compare factor counts & precision over rolling window (existing quality module)

## Immediate Findings (Snapshot)
- Missing dependency detection: `prometheus_client` import unresolved (ensure it's declared in `requirements.txt`).
- Correlation engine: rule conditions pattern-match factors; potential drift if factor names change—needs constant definitions or central enum.
- Lane execution: dynamic `__import__` for `LaneContext`; replace with direct import for clarity.
- Silent metric init failures swallowed (`except Exception: pass`)—consider narrowing exception scope.
- No explicit timeouts on potential future network calls (audit later in `integrations/`).

## Recommended Quick Wins (Week 1)
| Priority | Action | Effort (est) | Impact | Owner |
|----------|--------|--------------|--------|-------|
| P1 | Add `prometheus_client` to requirements + optional guard tests | 0.5h | Metrics stability | | 
| P1 | Introduce constants for factor names used in correlation rules | 1h | Reduce drift risk | | 
| P2 | Replace dynamic import of `LaneContext` with direct import | 0.25h | Clarity & tooling | | 
| P2 | Add test asserting all lane factors start with `lane_` | 0.5h | Governance | | 
| P3 | Bandit scan & address high findings | 2h | Security | | 
| P3 | Add replay determinism test diffing outputs | 1h | Reliability | | 

## Deeper Review Targets (Week 2–3)
- `core/decision_engine.py`
- `core/event_pipeline.py`
- `core/graph/hopgraph_lite.py` (potential performance hotspot)
- `core/quality/factor_quality.py` (statistical assumptions)
- `repositories/*` (data custody & transaction integrity)

## Risk Scoring Model
| Severity | Definition | Example |
|----------|-----------|---------|
| Critical | Immediate risk to correctness or security | Missed tenant isolation check |
| High | Likely to cause data or detection drift | Factor mislabel causes promotion error |
| Medium | Degradation potential under load | Blocking I/O in async path |
| Low | Maintainability / clarity only | Naming inconsistency |

## Reporting Template
```
Date: <YYYY-MM-DD>
Scope: <commit hash range>
Summary: <one paragraph>
Top Risks:
- [Critical] ...
Remediation ETA: <date>
Regression Gates: <automation added>
```

## Automation Hooks
Current Automation:
- `scripts/audit_runner.py` now performs: unresolved import scan, dependency usage diff, lint (ruff), bandit (HIGH -> fail), mypy subset, replay determinism, optional coverage, metrics scrape, suppression precision regression guard.
- GitHub Actions workflow: `.github/workflows/audit.yml` executes audit on push/PR with `--strict --coverage` and uploads `audit_results.json`.
 - Rubric scoring integration (`--metrics-json` + computed readiness rubric).
 - Cost ledger instrumentation for inference tiers (see `core/metrics/cost_ledger.py`).
 - FP taxonomy & classifier stub (`docs/fp_taxonomy.md`, `scripts/fp_classify.py`).
 - Multi-tenant isolation stress harness (`scripts/tenant_isolation_stress.py`).
 - Correlation before/after TP/FP counters (Prometheus: hunt_corr_tp_before_total, etc.).

Planned / Optional Enhancements:
- Add full module list to coverage gating (enforce minimum threshold).
- Integrate alert precision trend ingestion to auto-populate baseline for suppression regression.
- Add SBOM generation (e.g., `pip-audit` / cyclonedx) for supply chain reporting.
- Add JSON schema validation for replay scenario definitions.

Artifacts Produced:
- `audit_results.json` (central summary)
- `audit_artifacts/` (replay runs when enabled)
- Coverage terminal excerpt (embedded in audit JSON if `--coverage` used)

Regression Guard Parameters:
- `--precision-baseline <float>` and `--precision-current <float>` compare suppression precision.
- Fails phase if `(baseline - current) > --precision-regression-threshold` (default 0.01).

## Success Criteria
- All P1/P2 remediation complete within sprint.
- No unresolved imports.
- Correlation tests stable across two consecutive runs.
- Replay determinism diff = empty.
- Metrics endpoint exposes all expected counters/gauges/histograms.
 - Coverage trend stable or improving (define target e.g. >= 70% initially, ratchet +5% per quarter).
 - No HIGH Bandit findings; new findings auto-block PR merge.
 - Suppression precision regression phase passes or triggers explicit waiver review.

## Next Steps After This Plan
1. Approve scope & quick wins.
2. Implement automation script.
3. Execute scans & populate first report.
4. Triage backlog and assign owners.
5. Schedule verification run.

*Living document – update as architecture evolves.*
