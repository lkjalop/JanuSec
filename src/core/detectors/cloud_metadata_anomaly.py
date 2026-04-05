"""Detect anomalies in cloud metadata and IAM changes."""
from typing import Any, Dict, List

def detect_cloud_metadata_anomalies(runtime: Any) -> List[Dict[str,Any]]:
    results: List[Dict[str,Any]] = []
    if runtime is None:
        return results
    try:
        cloud_events = getattr(runtime, 'cloud_events', None) or []
        for e in cloud_events:
            try:
                et = e.get('event_type') or e.get('type')
                if et in ('iam_policy_change','instance_metadata_access','role_assumption'):
                    results.append({'factor':'cloud_metadata_anomaly','event_type':et,'resource':e.get('resource'),'score':0.65,'reason':f'cloud event {et} on {e.get("resource")}', 'metadata':{'mitre':['T1078','T1098'],'stride':['repudiation']}})
            except Exception:
                pass
    except Exception:
        pass
    return results
