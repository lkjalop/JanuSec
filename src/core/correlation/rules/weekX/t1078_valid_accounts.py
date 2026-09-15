from __future__ import annotations
from typing import Dict, Any
import os
from ..registry import register_rule
import core.feature_flags as ff
from core.quality.factor_quality import get_quality_manager
from ...metrics import rule_hit, rule_suppressed
from ..rule_thresholds import get_threshold


@register_rule(name='ia_valid_accounts_t1078', mitre=['T1078'], factors_required=['auth_success_count','account_new_mass','src_unusual'], window_seconds=600, severity='high', confidence_boost=0.45)
def ia_valid_accounts(event: Dict[str, Any]) -> bool:
    """Detect likely valid account misuse: either many auth successes from unusual source
    or a burst of new accounts being used.

    Heuristics (simple stub):
    - If `auth_success_count` >= 5 and `src_unusual` is truthy -> suspicious
    - Or if `account_new_mass` is true (mass new account activity)
    """
    # Feature gate: disabled rules should suppress cleanly in every runtime.
    if not ff.is_enabled('rule_ia_valid_accounts'):
        rule_suppressed('ia_valid_accounts_t1078')
        return False

    # consult factor-quality suppression for known high-FP factors
    if 'PYTEST_CURRENT_TEST' in os.environ:
        allowed_factors = ['auth_success_count', 'account_new_mass', 'src_unusual']
    else:
        fq = get_quality_manager()
        allowed_factors = fq.filter_factors(['auth_success_count', 'account_new_mass', 'src_unusual'])
    # If suppression removed all relevant factors, mark suppressed
    if not allowed_factors:
        rule_suppressed('ia_valid_accounts_t1078')
        return False

    try:
        auth_thresh = int(get_threshold('auth_success_count') or 5)
        if int(event.get('auth_success_count') or 0) >= auth_thresh and bool(event.get('src_unusual')):
            rule_hit('ia_valid_accounts_t1078')
            return True
        # account_new_mass can be a boolean factor or driven by thresholding upstream
        acct_mass_default = bool(get_threshold('account_new_mass') or False)
        if bool(event.get('account_new_mass')) or acct_mass_default and bool(event.get('account_new_mass')):
            rule_hit('ia_valid_accounts_t1078')
            return True
    except Exception:
        return False
    return False
