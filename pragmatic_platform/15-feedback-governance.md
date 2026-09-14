# Feedback Weight Decay & Governance

## Goals
- Prevent stale analyst feedback from exerting disproportionate influence.
- Bound any single factor's contribution to reduce runaway bias.
- Provide transparent, explainable decay surfaced via the /decisions/{id}/explain endpoint.

## Configuration (Env Vars)
| Variable | Default | Description |
|----------|---------|-------------|
| FEEDBACK_DECAY_HALF_LIFE_DAYS | 0 | If >0, applies exponential half-life decay to factor weights relative to last_updated timestamp. |
| FACTOR_WEIGHT_ABS_CAP | 0 | If >0, clamps absolute value of a (possibly decayed) weight to this maximum. |

## Decay Formula
```
EffectiveWeight = RawWeight * 0.5^(AgeSeconds / (HalfLifeDays * 86400))
```
Where AgeSeconds = now - last_updated.

If `FEEDBACK_DECAY_HALF_LIFE_DAYS=0`, decay is disabled (RawWeight used).

## Influence Cap
After decay, if `|EffectiveWeight| > FACTOR_WEIGHT_ABS_CAP` and cap > 0, clamp to ±cap.

## Explanation Endpoint Integration
`GET /api/v1/decisions/{id}/explain` returns, per factor:
```
{
  "factor": str,
  "weight_decayed": float | null,
  "feedback": { up_votes, down_votes, net, total }
}
```
Plus global fields: `decay_half_life_days`, `influence_cap`, `feedback_window`.

## Operational Guidance
- Begin pilot with no decay for 1 week to collect baseline, then introduce half-life (e.g., 14 days) and monitor confidence stability.
- Use a low cap initially (e.g., 3.0) if weights are roughly on scale ~[-5,5]; adjust after observing distribution.
- Consider periodic weight re-normalization if total magnitude drifts upward.

## Future Enhancements
- Per-factor adaptive decay: shorten half-life for rarely re-affirmed factors.
- Governance dashboard: show aging histogram of weights.
- Threshold-based archival: if a factor sees no feedback for 90 days, archive its weight to a history table.
