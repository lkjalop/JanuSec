"""DNS extraction utilities using dnspython when available.
Falls back to simple qname parsing heuristics when dnspython not installed.
"""
from __future__ import annotations
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

def extract_dns_from_payload(payload: bytes) -> Dict[str, Any]:
    """Attempt to parse DNS packet bytes and return qname, rcode, qtype, answers.
    Returns empty dict on failure.
    """
    try:
        try:
            import dns.message  # type: ignore
            import dns.name  # type: ignore
            import dns.rdatatype  # type: ignore
            msg = dns.message.from_wire(payload)
            qname = None
            qtype = None
            if msg.question:
                q = msg.question[0]
                qname = str(q.name)
                qtype = dns.rdatatype.to_text(q.rdtype)
            answers = []
            for rrset in msg.answer:
                for rr in rrset:
                    answers.append(str(rr))
            return {'qname': qname, 'qtype': qtype, 'answers': answers, 'rcode': msg.rcode()}
        except Exception:
            # Fallback: crude heuristic: look for ascii domain-like substring
            try:
                s = payload.decode('utf-8', errors='ignore')
                # find first token with a dot
                for tok in s.split():
                    if '.' in tok and len(tok) > 4:
                        return {'qname': tok, 'qtype': None, 'answers': [], 'rcode': None}
            except Exception:
                pass
    except Exception:
        pass
    return {}
