import time
from typing import Dict, Any
from .registry import register_rule

# 10 exemplar rules with simple heuristics that inspect event dict

@register_rule(name='suspicious_ssh_from_unusual_port', mitre=['T1021'], factors_required=['ip','port'], window_seconds=300, severity='medium', confidence_boost=0.1)
def suspicious_ssh(event: Dict[str, Any]) -> bool:
    # SSH on non-standard ports and from rare country code
    try:
        proto = event.get('protocol') or event.get('service') or ''
        port = int(event.get('dst_port') or event.get('port') or 0)
        if proto and 'ssh' in str(proto).lower() and port not in (22, 2222):
            return True
    except Exception:
        pass
    return False

@register_rule(name='multiple_failed_logins', mitre=['T1110'], factors_required=['failed_login_count'], window_seconds=600, severity='high', confidence_boost=0.3)
def failed_logins(event: Dict[str, Any]) -> bool:
    try:
        if int(event.get('failed_login_count', 0)) >= 5:
            return True
    except Exception:
        pass
    return False

@register_rule(name='suspicious_user_agent', mitre=['T1071'], factors_required=['user_agent'], window_seconds=3600, severity='low', confidence_boost=0.05)
def suspicious_ua(event: Dict[str, Any]) -> bool:
    ua = str(event.get('user_agent') or '')
    if ua and ('curl' in ua.lower() or 'wget' in ua.lower()) and not event.get('automation', False):
        return True
    return False

@register_rule(name='rare_ja3', mitre=['T1574'], factors_required=['ja3'], window_seconds=7200, severity='high', confidence_boost=0.4)
def rare_ja3(event: Dict[str, Any]) -> bool:
    ja3 = event.get('ja3_fingerprint')
    if ja3 and ja3.startswith('rare-'):
        return True
    return False

@register_rule(name='suspicious_domain_tld', mitre=['T1566'], factors_required=['domain'], window_seconds=3600, severity='medium', confidence_boost=0.2)
def suspicious_tld(event: Dict[str, Any]) -> bool:
    domain = str(event.get('domain') or '')
    if domain and domain.endswith('.xyz'):
        return True
    return False

@register_rule(name='process_lolbin', mitre=['T1218'], factors_required=['process'], window_seconds=3600, severity='medium', confidence_boost=0.2)
def lolbin_process(event: Dict[str, Any]) -> bool:
    proc = str(event.get('process') or '').lower()
    if proc and any(x in proc for x in ('certutil','mshta','bitsadmin','regsvr32')):
        return True
    return False

@register_rule(name='ip_and_domain_mismatch', mitre=['T1071'], factors_required=['ip','domain'], window_seconds=300, severity='low', confidence_boost=0.05)
def ip_domain_mismatch(event: Dict[str, Any]) -> bool:
    ip = str(event.get('dst_ip') or '')
    domain = str(event.get('domain') or '')
    if ip and domain and domain in ip:
        # trivial negative case
        return False
    if ip and domain and len(domain) > 0:
        return True
    return False

@register_rule(name='internal_scan_pattern', mitre=['T1595'], factors_required=['src_ip','scan_rate'], window_seconds=120, severity='high', confidence_boost=0.4)
def internal_scan(event: Dict[str, Any]) -> bool:
    try:
        rate = float(event.get('scan_rate') or 0)
        src = event.get('src_ip')
        if src and src.startswith('10.') and rate > 50.0:
            return True
    except Exception:
        pass
    return False

@register_rule(name='exfil_over_http', mitre=['T1041'], factors_required=['http_bytes_out'], window_seconds=3600, severity='high', confidence_boost=0.5)
def exfil_http(event: Dict[str, Any]) -> bool:
    try:
        out = int(event.get('http_bytes_out') or 0)
        if out > 1000000:
            return True
    except Exception:
        pass
    return False

@register_rule(name='new_user_agent_after_idle', mitre=['T1071'], factors_required=['user_agent','last_seen'], window_seconds=86400, severity='medium', confidence_boost=0.15)
def new_ua_after_idle(event: Dict[str, Any]) -> bool:
    try:
        last = float(event.get('last_seen') or 0)
        ua = str(event.get('user_agent') or '')
        if ua and last > 0 and (time.time() - last) > 86400:
            return True
    except Exception:
        pass
    return False
