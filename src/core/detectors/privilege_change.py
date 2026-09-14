"""Detect privilege change events from runtime event streams."""
from typing import Any, Dict, List

def detect_privilege_changes(runtime: Any) -> List[Dict[str,Any]]:
    results: List[Dict[str,Any]] = []
    if runtime is None:
        return results
    try:
        events = getattr(runtime, 'auth_events', None) or []
        for e in events:
            try:
                t = e.get('type') or ''
                if t in ('group_membership_change','privileged_logon','account_elevation'):
                    results.append({'factor':'privilege_change','event':t,'actor':e.get('actor'),'score':0.7,'reason':f'privileged event {t} for {e.get("actor")}', 'metadata':{'mitre':['T1078','T1098'],'stride':['elevation']}})
            except Exception:
                pass
    except Exception:
        pass
    return results
