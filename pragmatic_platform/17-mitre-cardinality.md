# MITRE / STRIDE Cardinality Strategy

## Goals
- Preserve low metric & label cardinality in Prometheus.
- Enable iterative expansion of factor->tactic mapping without exploding derived factors.

## Principles
1. **Stable Roots**: Only map normalized factor roots (before any dynamic suffixes).
2. **Cap Additions per Release**: Add ≤5 new mapped roots per iteration; observe impact.
3. **No Dynamic Token Expansion**: Avoid generating tactic tags from free-form strings.
4. **Audit Mapping Changes**: Maintain changelog section listing newly added mappings.
5. **Graceful Removal**: Deprecate rarely firing mappings after 30 days of inactivity.

## Metrics to Watch
| Metric | Purpose |
|--------|---------|
| `distinct_mitre_tags_total` (custom gauge) | Count unique tag variants seen (optional) |
| Factor frequency distribution | Detect skew from new tags |

## Change Control Checklist
- [ ] New mapping introduces at most 1 ATT&CK tactic per factor unless strong justification.
- [ ] Mapping does not cause >5% increase in average factor list length across replay sample.
- [ ] Replay harness run shows <2% unintended verdict flip rate due solely to new tags.

## Deprecation Process
1. Identify tags with zero occurrence in last 14 days.
2. Mark as candidate in mapping file comment.
3. Remove after next release if still unused.

## Future Enhancements
- Automatic mapping usage metrics endpoint.
- Mapping versioning header in explain endpoint.

