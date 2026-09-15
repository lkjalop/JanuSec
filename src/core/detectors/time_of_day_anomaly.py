"""Flag activity outside normal working hours per actor or batch.

Runtime may provide timestamps in events; we flag events between 00:00-05:00 by default.
"""
from typing import Any, Dict, List
import datetime

def detect_time_of_day_anomalies(runtime: Any, start_hour: int = 0, end_hour: int = 5) -> List[Dict[str,Any]]:
    results: List[Dict[str,Any]] = []
    if runtime is None:
        return results
    try:
        events = getattr(runtime, 'events', None) or []
        for e in events:
            try:
                ts = e.get('ts') or e.get('timestamp')
                if ts is None:
                    continue
                # Accept timestamps in seconds or ISO strings
                if isinstance(ts, (int,float)):
                    dt = datetime.datetime.utcfromtimestamp(float(ts))
                else:
                    try:
                        dt = datetime.datetime.fromisoformat(str(ts))
                    except Exception:
                        continue
                if dt.hour >= start_hour and dt.hour < end_hour:
                    results.append({'factor':'time_of_day_anomaly','actor': e.get('actor') or e.get('user'),'hour':dt.hour,'score':0.3,'reason':f'activity at hour {dt.hour}'} )
            except Exception:
                pass
    except Exception:
        pass
    return results
