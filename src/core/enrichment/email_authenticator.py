import time
import re
import base64
from typing import Any, Dict, Optional

import dkim
from dns.resolver import resolve, NXDOMAIN
from email import message_from_bytes


class DKIMVerifier:
    """Simple DKIM verifier using dkimpy and DNS TXT lookups with caching.

    verify_message_bytes accepts the raw email bytes and returns a dict with
    verification result and metadata. DNS TXT lookups are cached in-memory
    with a TTL (default 3600s) to avoid repeated network calls.
    """

    def __init__(self, dns_ttl_seconds: int = 3600):
        self.dns_cache: Dict[str, Dict[str, Any]] = {}
        self.dns_ttl_seconds = dns_ttl_seconds

    def _parse_dkim_header(self, msg_bytes: bytes) -> Dict[str, Optional[str]]:
        try:
            msg = message_from_bytes(msg_bytes)
            dkim_header = msg.get('DKIM-Signature')
            if not dkim_header:
                return {"selector": None, "domain": None, "raw": None}

            # dkim_header is a string containing semi-colon separated tags
            s_match = re.search(r"\bs=([^;\s]+)", dkim_header)
            d_match = re.search(r"\bd=([^;\s]+)", dkim_header)
            selector = s_match.group(1) if s_match else None
            domain = d_match.group(1) if d_match else None

            return {"selector": selector, "domain": domain, "raw": dkim_header}
        except Exception:
            return {"selector": None, "domain": None, "raw": None}

    def _fetch_txt(self, name: str) -> Optional[str]:
        now = time.time()
        entry = self.dns_cache.get(name)
        if entry and entry.get("expires_at", 0) > now:
            return entry.get("txt")

        try:
            answers = resolve(name, 'TXT')
            # dns.resolver returns a sequence of TXT records; join them
            txt = "".join([str(r.strings[0], 'utf-8') if hasattr(r, 'strings') and r.strings else str(r) for r in answers])
            self.dns_cache[name] = {"txt": txt, "expires_at": now + self.dns_ttl_seconds}
            return txt
        except NXDOMAIN:
            return None
        except Exception:
            return None

    def _extract_p_from_txt(self, txt: str) -> Optional[str]:
        # text like: "v=DKIM1; k=rsa; p=MIIBIjANBgkq..."
        m = re.search(r"\bp=([A-Za-z0-9+/=]+)", txt)
        if m:
            return m.group(1)
        return None

    def verify_message_bytes(self, msg_bytes: bytes) -> Dict[str, Any]:
        """Verify the DKIM signature on the provided raw message bytes.

        Returns a dict containing:
          - valid: bool
          - selector: str|None
          - signing_domain: str|None
          - public_key_present: bool
          - public_key_b64: str|None
          - failure_reason: Optional[str]
        """
        parsed = self._parse_dkim_header(msg_bytes)
        selector = parsed.get("selector")
        signing_domain = parsed.get("domain")

        result: Dict[str, Any] = {
            "valid": False,
            "selector": selector,
            "signing_domain": signing_domain,
            "public_key_present": False,
            "public_key_b64": None,
            "failure_reason": None,
        }

        # Quick check: if no DKIM header, short-circuit
        if not selector or not signing_domain:
            result["failure_reason"] = "No DKIM-Signature header found or missing s=/d="
            return result

        # Use dkimpy to verify signature (it will perform DNS lookup internally)
        try:
            valid = dkim.verify(msg_bytes)
            result["valid"] = bool(valid)
        except Exception as e:
            result["failure_reason"] = f"dkim.verify exception: {e}"

        # Try to fetch public key TXT record: <selector>._domainkey.<domain>
        txt_name = f"{selector}._domainkey.{signing_domain}"
        txt = self._fetch_txt(txt_name)
        if txt:
            p_b64 = self._extract_p_from_txt(txt)
            if p_b64:
                result["public_key_present"] = True
                result["public_key_b64"] = p_b64
        else:
            # no key found; annotate but don't fail here
            if result.get("failure_reason") is None:
                result["failure_reason"] = "DKIM public key DNS TXT not found"

        return result


__all__ = ["DKIMVerifier"]
