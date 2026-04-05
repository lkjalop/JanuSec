from typing import List
from ..canonical_event import CanonicalEvent

class FactorEmit(dict):
    pass

def extract_iam_factors(events: List[CanonicalEvent]) -> List[FactorEmit]:
    out: List[FactorEmit] = []
    by_user = {}
    for e in events:
        if e.source_type != 'iam':
            continue
        by_user.setdefault(e.user or 'unknown', []).append(e)
    for user, lst in by_user.items():
        lst.sort(key=lambda x: x.timestamp)
        role_changes = 0
        mfa_disabled = False
        password_resets = 0
        inactive_reactivation = False
        for ev in lst:
            if ev.privilege_level_before and ev.privilege_level_after and ev.privilege_level_before != ev.privilege_level_after:
                role_changes += 1
            if ev.action and 'disable_mfa' in ev.action.lower():
                mfa_disabled = True
            if ev.action and 'password_reset' in ev.action.lower():
                password_resets += 1
            if ev.action and 'reactivate' in ev.action.lower() and (ev.privilege_level_before in {None,'inactive'}):
                inactive_reactivation = True
        if role_changes >= 1:
            out.append(FactorEmit(name='privilege_escalation', nodes=[f"user:{user}"], domain='iam', confidence=0.75, ts=lst[-1].timestamp))
        if role_changes >= 3:
            out.append(FactorEmit(name='role_chaining_spike', nodes=[f"user:{user}"], domain='iam', confidence=0.65, ts=lst[-1].timestamp))
        if mfa_disabled:
            out.append(FactorEmit(name='mfa_disabled', nodes=[f"user:{user}"], domain='iam', confidence=0.7, ts=lst[-1].timestamp))
        if password_resets >= 3:
            out.append(FactorEmit(name='password_reset_storm', nodes=[f"user:{user}"], domain='iam', confidence=0.55, ts=lst[-1].timestamp))
        if inactive_reactivation:
            out.append(FactorEmit(name='inactive_role_reactivation', nodes=[f"user:{user}"], domain='iam', confidence=0.6, ts=lst[-1].timestamp))
    return out
