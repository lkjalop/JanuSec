from typing import List, Dict, Any, Optional
import time


def correlate_events_time_window(iam_events: List[Dict[str, Any]], other_events: List[Dict[str, Any]], window_seconds: int = 300) -> List[Dict[str, Any]]:
    """
    Correlate IAM events with other event streams (supply-chain, cloud) within a time window.
    Returns list of correlated pairs with delta and combined context.
    """
    out = []
    # Normalize timestamps as float seconds
    def ts(e):
        return float(e.get('eventTime', e.get('ts', time.time())))

    other_sorted = sorted(other_events, key=ts)
    for ie in iam_events:
        its = ts(ie)
        # find other events within window
        for oe in other_sorted:
            ots = ts(oe)
            if abs(its - ots) <= window_seconds:
                out.append({'iam': ie, 'other': oe, 'delta': its - ots})
    return out
