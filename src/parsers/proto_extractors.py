from __future__ import annotations

from typing import Dict, Any
import re


def extract_http(payload_text: str) -> Dict[str, Any]:
    """Extract HTTP fields: method, path, host, user-agent."""
    res = {'http': False, 'method': None, 'path': None, 'host': None, 'user_agent': None}
    lines = payload_text.splitlines()
    if not lines:
        return res
    m = re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/', lines[0])
    if m:
        res['http'] = True
        res['method'] = m.group(1)
        res['path'] = m.group(2)
        for ln in lines[1:20]:
            if ln.lower().startswith('host:'):
                res['host'] = ln.split(':',1)[1].strip()
            if ln.lower().startswith('user-agent:'):
                res['user_agent'] = ln.split(':',1)[1].strip()
    return res


def extract_dns(payload_text: str) -> Dict[str, Any]:
    """Very small DNS heuristic: look for qname patterns and NXDOMAIN markers."""
    res = {'dns': False, 'qname': None, 'nxdomain': False}
    # detect simple qname
    m = re.search(r'([a-z0-9\-]+\.)+[a-z]{2,}', payload_text, re.I)
    if m:
        res['dns'] = True
        res['qname'] = m.group(0)
    if 'NXDOMAIN' in payload_text or 'nxdomain' in payload_text.lower():
        res['nxdomain'] = True
    return res


def extract_ja3(payload_text: str) -> Dict[str, Any]:
    """Stub: detect TLS ClientHello JA3-like string patterns in text."""
    res = {'ja3': None}
    m = re.search(r'JA3:([0-9,\.]*)', payload_text)
    if m:
        res['ja3'] = m.group(1)
    return res
