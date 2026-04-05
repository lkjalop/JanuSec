"""Simple deterministic heuristics for DKIM/SPF/DMARC and PII redaction."""

import re
import hashlib
from typing import Dict, Any


EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


def redact_pii(text: str) -> str:
    # Replace emails and long hex-like tokens with placeholders
    if not isinstance(text, str):
        return text
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    # redact credit card-like sequences (13-19 digits with optional separators)
    text = re.sub(r"\b(?:\d[ -]*?){13,19}\b", "[REDACTED_CC]", text)
    # redact long hex-looking strings
    text = re.sub(r"\b[0-9a-fA-F]{32,}\b", "[REDACTED_HASH]", text)
    return text


def compute_sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dkim_check(headers: Dict[str, str]) -> Dict[str, Any]:
    # deterministic heuristic: pass if 'DKIM-Signature' header exists
    return {"passed": "DKIM-Signature" in headers, "details": headers.get("DKIM-Signature")}


def spf_check(mail_from: str, return_path: str) -> Dict[str, Any]:
    # naive heuristic: pass if domains match
    try:
        m1 = mail_from.split("@", 1)[1]
        m2 = return_path.split("@", 1)[1]
        return {"passed": m1 == m2, "mail_from": mail_from, "return_path": return_path}
    except Exception:
        return {"passed": False}


def dmarc_evaluate(domain: str, dkim_result: Dict[str, Any], spf_result: Dict[str, Any]) -> Dict[str, Any]:
    # simple policy: pass if either DKIM or SPF passed
    passed = bool(dkim_result.get("passed") or spf_result.get("passed"))
    return {"domain": domain, "passed": passed, "dkim": dkim_result, "spf": spf_result}
