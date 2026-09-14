"""Clean email adapter utilities for unit tests.

Deterministic helpers used by tests: PII redaction, SHA256 hashing of strings,
an `EmailAdapter` scaffold for canonicalization, and naive DKIM/SPF/DMARC
heuristics. No network calls or provider SDKs are included.
"""

from dataclasses import dataclass
import hashlib
import logging
import re
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


def redact_pii(text: Optional[str]) -> Optional[str]:
    if text is None:
        return text
    text = re.sub(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+", "[REDACTED_EMAIL]", text)
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[REDACTED_SSN]", text)
    text = re.sub(r"\b(?:\d[ -]*?){13,16}\b", "[REDACTED_CC]", text)
    return text


def compute_sha256_hex(s: Optional[str]) -> str:
    if s is None:
        s = ""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


@dataclass
class OAuthConfig:
    client_id: str
    client_secret: str
    tenant: Optional[str] = None
    scopes: Optional[List[str]] = None


class EmailAdapter:
    """Scaffold for canonicalizing email messages in unit tests."""

    def __init__(self, oauth: OAuthConfig, provider: str = "m365"):
        self.oauth = oauth
        self.provider = provider

    def fetch_messages(self, since: Optional[str] = None, max_items: int = 100) -> List[Dict[str, Any]]:
        return []

    def canonicalize_message(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        body = (raw.get("body") or "")
        redacted = redact_pii(body)
        return {
            "id": raw.get("id"),
            "ts": raw.get("date") or raw.get("ts"),
            "from": raw.get("from"),
            "to": raw.get("to"),
            "subject": raw.get("subject"),
            "body_text": redacted,
            "body_hash": compute_sha256_hex(redacted),
            "attachments": [
                {"name": a.get("name"), "sha256": compute_sha256_hex(a.get("content", ""))}
                for a in (raw.get("attachments") or [])
            ],
        }


class DKIMVerifier:
    def verify(self, headers: Optional[Dict[str, str]], body: Optional[str]) -> bool:
        if not headers:
            return False
        sig = headers.get("DKIM-Signature")
        return bool(sig and "b=" in sig)


class SPFChecker:
    def check(self, ip: Optional[str], domain: Optional[str]) -> str:
        if not ip:
            return "neutral"
        if ip.startswith("192.") or ip.startswith("10.") or ip.startswith("127."):
            return "pass"
        return "neutral"


class DMARCPolicy:
    def evaluate(self, domain: Optional[str], spf: str, dkim: bool) -> str:
        if spf == "pass" or dkim:
            return "none"
        return "quarantine"
