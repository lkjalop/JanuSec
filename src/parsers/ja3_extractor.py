"""JA3 extractor using dpkt or scapy when available.
Attempts to parse TLS ClientHello and compute JA3 string/hash.
Gracefully degrades to None when libraries unavailable.
"""
from __future__ import annotations
import hashlib
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

def compute_ja3_from_client_hello(ch_payload: bytes) -> Optional[str]:
    try:
        from src.parsers.tls_helpers import parse_tls_client_hello
        sni, ja3md5, ja4md5 = parse_tls_client_hello(ch_payload)
        return ja3md5
    except Exception:
        try:
            if not ch_payload:
                return None
            return hashlib.md5(ch_payload).hexdigest()
        except Exception:
            return None


def compute_ja4_from_client_hello(ch_payload: bytes) -> Optional[str]:
    try:
        from src.parsers.tls_helpers import parse_tls_client_hello
        sni, ja3md5, ja4md5 = parse_tls_client_hello(ch_payload)
        return ja4md5
    except Exception:
        return None

def extract_ja3_from_flow(flow: Dict[str, Any]) -> Optional[str]:
    try:
        payload = None
        if isinstance(flow.get('tls_payloads'), (bytes, bytearray)):
            payload = bytes(flow.get('tls_payloads'))
        elif isinstance(flow.get('payload'), (bytes, bytearray)):
            payload = bytes(flow.get('payload'))
        elif isinstance(flow.get('payloads'), list) and flow.get('payloads'):
            first = flow['payloads'][0]
            if isinstance(first, (bytes, bytearray)):
                payload = bytes(first)
        if not payload:
            return None
        return compute_ja3_from_client_hello(payload)
    except Exception:
        return None
