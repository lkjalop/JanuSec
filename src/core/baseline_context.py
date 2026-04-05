from __future__ import annotations

import asyncio
from typing import Any, Dict, Tuple

from src.core.baseline_service import BASELINES


def _extract_entity(event: Dict[str, Any]) -> Tuple[str | None, str | None]:
    if not isinstance(event, dict):
        return None, None
    for key, etype in (('user', 'user'), ('host', 'host'), ('src_ip', 'ip'), ('ip', 'ip')):
        val = event.get(key)
        if val:
            return etype, str(val)
    return None, None


async def _update_baseline_async(
    event: Dict[str, Any],
    tenant_id: str | None,
    *,
    value: float,
    metric: str = 'factor_count',
) -> Dict[str, Any]:
    if BASELINES is None:
        return {}
    etype, eid = _extract_entity(event)
    if not etype or not eid:
        return {}
    tenant_key = tenant_id or 'default'
    entity_id = f'{tenant_key}:{eid}'
    rec = await BASELINES.update(etype, entity_id, metric, float(value))
    z = rec.z_score(float(value))
    mean = rec.mean
    baseline_frequency = float(value) / mean if mean > 0 else 0.0
    baseline_noise = rec.count >= 5 and abs(z) < 1.0
    return {
        'baseline_frequency': round(baseline_frequency, 4),
        'baseline_noise': baseline_noise,
        'baseline_z': round(z, 3),
        'baseline_samples': rec.count,
        'baseline_mean': round(mean, 4),
        'baseline_metric': metric,
        'baseline_entity_type': etype,
        'baseline_entity_id': entity_id,
    }


def build_baseline_context(
    event: Dict[str, Any],
    tenant_id: str | None,
    *,
    value: float,
    metric: str = 'factor_count',
) -> Dict[str, Any]:
    """Sync wrapper around baseline updates for non-async callsites."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # Best-effort: skip async baseline update in sync caller
        return {}
    return asyncio.run(_update_baseline_async(event, tenant_id, value=value, metric=metric))


__all__ = ['build_baseline_context', '_update_baseline_async']
