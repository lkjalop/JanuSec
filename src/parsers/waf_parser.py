"""WAF log parser (skeleton): supports ModSecurity and AWS WAF JSON formats.

This is a minimal parser that extracts key fields useful for correlation: src_ip,
uri, method, status, rule_id, message, and timestamp. Meant to be extended.
"""
from __future__ import annotations
import json
import time
from typing import Dict, Any


def parse_waf_log(line: str) -> Dict[str, Any]:
    """Parse a single WAF log line (JSON) and return normalized dict.

    If parsing fails, raises ValueError.
    """
    try:
        obj = json.loads(line)
    except Exception as e:
        raise ValueError(f'bad_json:{e}')

    out: Dict[str, Any] = {'raw': obj}
    # Common keys for ModSecurity-like logs
    out['timestamp'] = obj.get('timestamp') or obj.get('time') or time.time()
    # AWS WAF sample structure may nest fields under 'httpRequest'
    http = obj.get('httpRequest') or obj.get('request') or {}
    out['src_ip'] = http.get('clientIp') or obj.get('clientIp') or obj.get('src_ip')
    out['uri'] = http.get('uri') or http.get('requestUri') or obj.get('uri') or obj.get('request_uri')
    out['method'] = http.get('method') or obj.get('method')
    out['status'] = obj.get('status') or http.get('status')
    # ModSecurity sometimes includes 'ruleId' or 'rule_id' and a message
    out['rule_id'] = obj.get('ruleId') or obj.get('rule_id') or obj.get('rule')
    out['message'] = obj.get('message') or obj.get('msg') or obj.get('matchedData')
    return out
