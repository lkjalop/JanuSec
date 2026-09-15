from typing import Any, Dict, Iterable


def get_proc_name(e: Dict[str, Any]) -> str:
    for k in ('proc_name', 'process', 'process_name'):
        v = e.get(k)
        if isinstance(v, str) and v:
            return v
    return ''


def has_proc_substr(e: Dict[str, Any], substr: str) -> bool:
    substr_l = str(substr).lower()
    for k in ('proc_name', 'process', 'process_name', 'parent_process', 'child_process'):
        v = e.get(k)
        if isinstance(v, str) and substr_l in v.lower():
            return True
    return False


def get_cmdline(e: Dict[str, Any]) -> str:
    for k in ('command_line', 'cmdline', 'cmd'):
        v = e.get(k)
        if isinstance(v, str) and v:
            return v
    return ''


def domain_is_rare(e: Dict[str, Any]) -> bool:
    return bool(e.get('rare_domain') or e.get('domain_rare') or e.get('ja3_rare'))


def _scan_nested_for_http(obj: Any) -> bool:
    try:
        if not obj:
            return False
        if isinstance(obj, str):
            s = obj.lower()
            return ('http://' in s) or ('https://' in s)
        if isinstance(obj, dict):
            for v in obj.values():
                if isinstance(v, str) and _scan_nested_for_http(v):
                    return True
                if isinstance(v, (list, dict)) and _scan_nested_for_http(v):
                    return True
        if isinstance(obj, list):
            for item in obj:
                if _scan_nested_for_http(item):
                    return True
    except Exception:
        return False
    return False


def cmdline_or_nested_has_http(e: Dict[str, Any], nested_keys: Iterable[str] = ('children', 'child_processes', 'related', 'neighbors')) -> bool:
    cl = get_cmdline(e)
    if 'http://' in cl.lower() or 'https://' in cl.lower():
        return True
    for k in nested_keys:
        if k in e and _scan_nested_for_http(e.get(k)):
            return True
    return False


def get_http_bytes_out(e: Dict[str, Any]) -> int:
    for k in ('http_bytes_out', 'http_bytes', 'bytes_out', 'net:bytes_out'):
        v = e.get(k)
        try:
            if v is not None:
                return int(v)
        except Exception:
            continue
    return 0


def normalize_service_stop_edr(e: Dict[str, Any]) -> None:
    try:
        act = str(e.get('action') or '').lower()
        svc = str(e.get('service_name') or '').lower()
        svc_disp = str(e.get('service_display_name') or '').lower()
        svc_bin = str(e.get('service_binary') or '').lower()
        if act == 'service_stop' and svc:
            edr_indicators = (
                'defend', 'defender', 'windowsdefender', 'microsoft defender',
                'crowdstrike', 'carbon', 'mcafee', 'symantec', 'trend', 'sophos',
                'sentinel', 'sentinelone', 'carbonblack', 'tanium', 'osquery'
            )
            combined = ' '.join((svc, svc_disp, svc_bin))
            if any(tok in combined for tok in edr_indicators):
                e.setdefault('service_stop_edr', True)
                e.setdefault('admin_context_change', True)
    except Exception:
        pass
