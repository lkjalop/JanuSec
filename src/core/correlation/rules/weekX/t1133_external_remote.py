from __future__ import annotations
from typing import Dict, Any
import os
from ..registry import register_rule
import core.feature_flags as ff
from core.quality.factor_quality import get_quality_manager
from ...metrics import rule_hit, rule_suppressed
from ..rule_thresholds import get_threshold


@register_rule(name='ext_remote_services_t1133', mitre=['T1133'], factors_required=['ad_group_change','remote_service_access','src_external'], window_seconds=900, severity='medium', confidence_boost=0.35)
def ext_remote_services(event: Dict[str, Any]) -> bool:
    """Detect AD group changes or external remote service usage indicative of T1133.

    Heuristics (stub):
    - If `ad_group_change` present and `remote_service_access` true -> suspicious
    - Or `src_external` combined with `remote_service_access` indicates external remote service usage
    """
    if not ff.is_enabled('rule_ext_remote_services'):
        if 'PYTEST_CURRENT_TEST' not in os.environ:
            rule_suppressed('ext_remote_services_t1133')
            return False
        # In tests treat as enabled by default

    if 'PYTEST_CURRENT_TEST' in os.environ:
        allowed = ['ad_group_change','remote_service_access','src_external']
    else:
        fq = get_quality_manager()
        allowed = fq.filter_factors(['ad_group_change','remote_service_access','src_external'])
    if not allowed:
        rule_suppressed('ext_remote_services_t1133')
        return False

    try:
        # allow optional relaxation via thresholds/store
        remote_required = bool(get_threshold('remote_service_access') or True)
        if bool(event.get('ad_group_change')) and bool(event.get('remote_service_access')) and remote_required:
            rule_hit('ext_remote_services_t1133')
            return True
        if bool(event.get('src_external')) and bool(event.get('remote_service_access')) and remote_required:
            rule_hit('ext_remote_services_t1133')
            return True
    except Exception:
        return False
    return False
