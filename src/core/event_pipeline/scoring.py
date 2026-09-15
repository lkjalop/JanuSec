from __future__ import annotations

from typing import Any, Dict, List, Tuple


MISSING_FIELD_WEIGHTS = {
    'host': 0.2,
    'user': 0.15,
    'parent_process': 0.2,
    'signer': 0.15,
    'network': 0.2,
}


def _value_from(event: dict[str, Any], keys: List[str]) -> Any:
    for key in keys:
        if not key:
            continue
        if key in event and event[key]:
            return event[key]
    ctx = event.get('context')
    if isinstance(ctx, dict):
        for key in keys:
            if key in ctx and ctx[key]:
                return ctx[key]
    return None


def _normalize_bool(val: Any) -> bool:
    if val is None:
        return False
    if isinstance(val, bool):
        return val
    text = str(val).strip().lower()
    return text in {'true', '1', 'yes', 'valid', 'signed'}


def adjust_confidence(event: dict[str, Any], factors: list[str], confidence: float) -> Tuple[float, Dict[str, Any]]:
    """Apply simple trust / uncertainty adjustments to the blended confidence.

    Returns adjusted confidence and metadata describing applied deltas.
    """
    metadata: Dict[str, Any] = {
        'missing_fields': [],
        'trust_signals': [],
        'extra_factors': [],
        'uncertainty_penalty': 0.0,
        'uncertainty_cap': 1.0,
        'tier': 'tier2',
    }

    missing_fields: List[str] = []
    trust_signals: List[str] = []

    host = _value_from(event, ['host', 'hostname', 'device_hostname', 'device_name', 'asset_name'])
    user = _value_from(event, ['user', 'username', 'userprincipalname', 'account', 'account_name'])
    parent = _value_from(event, ['parent_process', 'parent'])
    signer = _value_from(event, ['signature_subject', 'signature_issuer', 'signer', 'publisher', 'vendor'])
    network_present = bool(event.get('network') or event.get('network_context'))

    if not host:
        missing_fields.append('host')
    if not user:
        missing_fields.append('user')
    if not parent:
        missing_fields.append('parent_process')
    if not signer:
        missing_fields.append('signer')
    if not network_present:
        missing_fields.append('network')

    penalty = 0.0
    for field in missing_fields:
        penalty += MISSING_FIELD_WEIGHTS.get(field, 0.15)
        metadata['extra_factors'].append(f'needs_enrichment:{field}')
    penalty = min(0.95, round(penalty, 2))
    uncertainty_cap = max(0.05, 1.0 - penalty)

    trust_penalty = 0.0
    flag_name = str(event.get('flag_name') or event.get('flag') or '').lower()
    if flag_name.startswith('verified'):
        trust_penalty += 0.45
        trust_signals.append('flag:verified')
    if _normalize_bool(event.get('signature_valid') or event.get('signed') or event.get('signature_status')):
        trust_penalty += 0.3
        trust_signals.append('signature:valid')
    if any(f.startswith('allowlist_') for f in factors):
        trust_penalty += 0.2
        trust_signals.append('allowlist')

    adjusted = max(0.0, confidence - trust_penalty)
    adjusted = min(adjusted, uncertainty_cap)

    metadata['missing_fields'] = missing_fields
    metadata['trust_signals'] = trust_signals
    metadata['uncertainty_penalty'] = penalty
    metadata['uncertainty_cap'] = uncertainty_cap

    enriched_factors = [f for f in factors if not f.startswith('timings:')]
    core_factor_count = len(enriched_factors)

    if penalty >= 0.5:
        tier = 'needs_enrichment'
    elif core_factor_count <= 1 and adjusted < 0.45:
        tier = 'monitor'
    elif adjusted >= 0.65 and penalty < 0.5:
        tier = 'tier1'
    else:
        tier = 'tier2'

    metadata['tier'] = tier
    return adjusted, metadata
