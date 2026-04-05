# Multi-Tenant Isolation Design

## Motivation
Current runtime state (hash history, NX tracker, EWMA history, factor labels) is global. For production multi-customer deployments we need strict isolation and per-tenant overrides.

## Objectives
- Namespace volatile maps by tenant id (hash rarity, NX rate, ewma correlations, beacon scores).
- Tenant-scoped factor suppression & confidence weights.
- Minimal memory overhead via on-demand map creation + LRU eviction.
- Backward compatibility: if no tenant header -> use "global" namespace.

## Namespaced Structures
| Component              | Current Type                              | Proposed Type                                   |
|------------------------|-------------------------------------------|------------------------------------------------|
| file_hash_factors      | defaultdict[str, deque[float]]            | dict[tenant_id, defaultdict[str, deque[float]]] |
| nx_rate_tracker        | defaultdict[str, deque[bool]]             | dict[tenant_id, defaultdict[str, deque[bool]]]  |
| ewma_history           | dict[str, (float,float)]                  | dict[tenant_id, dict[str,(float,float)]]        |
| beacon_scores          | dict[str, (float, dict, float)]          | dict[tenant_id, dict[str,(float,dict,float)]]   |
| fp_labels              | dict[str, dict]                           | dict[tenant_id, dict[str, dict]]                |
| factor_weights         | env / file                                | dict[tenant_id, dict[str,float]]                |

## API Changes
- Accept `X-Tenant-ID` header on session build, replay diff, labeling endpoints.
- Extended health returns per-tenant breakdown when header provided.

## Isolation Strategy
1. Wrapper accessors: `get_tenant_runtime(app, tenant_id)` returning a lightweight view object with tenant-specific maps.
2. Lazy map creation: allocate underlying tenant dict only on first write.
3. Global eviction: background cleanup loop prunes inactive tenant maps based on last access timestamp (env `TENANT_INACTIVE_TTL_SECONDS`).
4. Memory guard rails per tenant (env `TENANT_MAX_HASH_KEYS`, `TENANT_MAX_NX_PRODUCERS`).

## Factor Suppression
- Maintain `suppressed_factors[tenant_id] -> set[str]`.
- Label endpoint stores labels under `runtime.fp_labels[tenant_id]`.
- Observed flags extended with tenant dimension: `set_observed(factor, bool, tenant_id=None)`.

## Confidence Weights
- Allow `FACTOR_CONFIDENCE_WEIGHTS_PATH` to contain directory of `{tenant}.yaml`.
- Fallback order: tenant-specific file > global file > inline env JSON > default weights.

## Persistence
- Session JSON path includes tenant prefix: `data/sessions/{tenant}/{session-id}.json`.
- EWMA history per tenant file: `data/sessions/{tenant}/ewma_history.json`.

## Metrics
Add `tenant` label to existing metrics where cardinality acceptable:
- `detector_factor_total{factor,tenant}`
- `detector_factor_fp_ratio{factor,tenant}`
- `session_confidence{tenant}`
Guard rails: enforce max tenants for metrics labeling (`METRICS_MAX_TENANTS`). If exceeded, fall back to unlabelled global aggregation to avoid explosion.

## Migration Path
Phase 1: Introduce tenant wrappers & header parsing, keep global maps as default.
Phase 2: Persist per-tenant sessions & ewma history.
Phase 3: Add metrics tenant labels & suppression sets.
Phase 4: Implement eviction & memory caps.

## Edge Cases
- Missing tenant header: use "global" partition; do not duplicate metrics.
- Excess tenants beyond cap: log warning, skip metrics with tenant label.
- Replay diff without tenant context: diff across global only; phase 2 will add multi-tenant diff.

## Open Questions
- Should factor weights fallback chain include tenant groups (e.g., vertical: finance vs healthcare)?
- Need encryption at rest per tenant directory? (future compliance requirement)

## Implementation Steps
1. Extend `ServerRuntime` with `tenants` mapping holding per-tenant runtime objects.
2. Refactor accessors in endpoints to pick tenant partition (header, query param, or default global).
3. Update cleanup loop to prune inactive tenant partitions.
4. Add tests for isolation (two tenants, distinct hash rarity baselines).

## Success Criteria
- Two different `X-Tenant-ID` headers produce distinct session histories and hash rarity counts.
- No cross-contamination (factors labeled in tenant A do not suppress in tenant B).
- Metrics exposed with tenant label when under cardinality cap.
