from typing import Dict, Any, Optional
import re

# Optional cryptographic DKIM verification via dkimpy
try:
    import dkim  # type: ignore
    _DKIM_AVAILABLE = True
except Exception:
    _DKIM_AVAILABLE = False


def parse_dkim(header_value: Optional[str]) -> Dict[str, Any]:
    if not header_value:
        return {"dkim": {"present": False}}
    # Very lightweight parse: extract d= (domain) and s= (selector)
    domain = _extract_kv(header_value, "d")
    selector = _extract_kv(header_value, "s")
    return {
        "dkim": {
            "present": True,
            "domain": domain,
            "selector": selector,
        }
    }


def verify_dkim(message_bytes: Optional[bytes]) -> Dict[str, Any]:
    """Cryptographically verify DKIM signature per RFC 6376 if dkimpy is available.

    Returns a dict with keys:
      - verified: bool | None
      - domain: Optional[str]
      - selector: Optional[str]
      - error: Optional[str]
    """
    if not message_bytes:
        return {"dkim": {"verified": None, "domain": None, "selector": None, "error": "no_message"}}
    if not _DKIM_AVAILABLE:
        return {"dkim": {"verified": None, "domain": None, "selector": None, "error": "dkimpy_not_installed", "hint": "install dkimpy (pip install dkimpy) and provide raw RFC822 message to enable cryptographic verification"}}
    try:
        # dkim.verify expects raw RFC822 message bytes
        verified = bool(dkim.verify(message_bytes))
        # Attempt to extract domain/selector from DKIM-Signature header in raw bytes
        try:
            hdr = _extract_header_bytes(message_bytes, b"DKIM-Signature")
            domain = _extract_kv(hdr.decode(errors="ignore"), "d") if hdr else None
            selector = _extract_kv(hdr.decode(errors="ignore"), "s") if hdr else None
        except Exception:
            domain = None
            selector = None
        return {"dkim": {"verified": verified, "domain": domain, "selector": selector, "error": None}}
    except Exception as e:
        return {"dkim": {"verified": False, "domain": None, "selector": None, "error": str(e)}}


def is_dkim_available() -> bool:
    """Return whether cryptographic DKIM verification is available in runtime."""
    return bool(_DKIM_AVAILABLE)


def parse_spf(header_value: Optional[str]) -> Dict[str, Any]:
    if not header_value:
        return {"spf": {"result": None}}
    # Common format: Received-SPF: Pass (sender SPF authorized) client-ip=203.0.113.1; envelope-from=...
    m = re.search(r"Received-SPF:\s*(\w+)", header_value, re.IGNORECASE)
    result = m.group(1).lower() if m else None
    return {"spf": {"result": result}}


def _extract_kv(s: str, key: str) -> Optional[str]:
    # Extract key=value tokens from DKIM-Signature header
    m = re.search(rf"\b{re.escape(key)}=([^;\s]+)", s)
    return m.group(1) if m else None


def _extract_header_bytes(message_bytes: bytes, header_name: bytes) -> Optional[bytes]:
    """Extract a raw header line by name from RFC822 message bytes (best-effort)."""
    try:
        # Split headers/body at first blank line
        headers_part = message_bytes.split(b"\r\n\r\n", 1)[0]
        # Find start of the header
        for line in headers_part.split(b"\r\n"):
            if line.lower().startswith(header_name.lower() + b":"):
                return line
    except Exception:
        pass
    return None


def redact_pii(text: Optional[str]) -> Optional[str]:
    if not text:
        return text
    # Redact emails and simple phone numbers
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", text)
    text = re.sub(r"\b\+?\d{1,3}[\s-]?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b", "[REDACTED_PHONE]", text)
    return text


def attachment_hashes(attachments: Optional[Any]) -> Dict[str, Any]:
    # Expect a list of dicts with bytes or content; here we just extract precomputed hashes if present
    hashes = []
    if isinstance(attachments, list):
        for a in attachments:
            h = None
            if isinstance(a, dict):
                h = a.get("sha256") or a.get("sha1") or a.get("md5")
            if h:
                hashes.append(h)
    return {"attachment_hashes": hashes}
