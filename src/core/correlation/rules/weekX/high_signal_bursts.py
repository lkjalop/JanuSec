from typing import Dict, Any
from ..registry import register_rule
from ..rule_thresholds import get_threshold


@register_rule(name='lateral_connection_burst', mitre=['T1021'], factors_required=['src_ip','dst_ip','dst_port'], window_seconds=120, severity='high', confidence_boost=0.6)
def lateral_burst(event: Dict[str, Any]) -> bool:
    try:
        cc = int(event.get('conn_count') or 0)
        src = event.get('src_ip')
        threshold = int(get_threshold('lateral_conn_count') or 30)
        if src and cc >= threshold:
            return True
    except Exception:
        pass
    return False


@register_rule(name='rapid_internal_scan', mitre=['T1595'], factors_required=['src_ip','scan_rate'], window_seconds=60, severity='high', confidence_boost=0.6)
def rapid_scan(event: Dict[str, Any]) -> bool:
    try:
        rate = float(event.get('scan_rate') or 0)
        src = event.get('src_ip')
        threshold = float(get_threshold('rapid_scan_rate') or 100.0)
        # simple private-space check; adjust as needed for IPv6
        if src and (src.startswith('10.') or src.startswith('192.168.') or src.startswith('172.')) and rate > threshold:
            return True
    except Exception:
        pass
    return False


@register_rule(name='exfil_traffic_spike', mitre=['T1041'], factors_required=['http_bytes_out','src_ip'], window_seconds=300, severity='high', confidence_boost=0.7)
def exfil_spike(event: Dict[str, Any]) -> bool:
    try:
        out = int(event.get('http_bytes_out') or 0)
        threshold = int(get_threshold('exfil_bytes') or 5_000_000)
        if out > threshold:
            return True
    except Exception:
        pass
    return False
