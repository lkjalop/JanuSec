"""Reversible IOC tokenization for sovereignty-preserving LLM routing.

Security telemetry contains data many SOCs cannot send to a third-party API: internal
IPs, usernames, hostnames, AWS ARNs. This module tokenizes those entities to opaque,
type-tagged placeholders (``IP_001``, ``USER_002``, ``HOST_003``) before an outbound
LLM call and restores the real values in the response. The model still reasons over the
*relationships* between tokens (``USER_002`` accessed ``HOST_003`` from ``IP_001``); only
the literal identifiers are withheld.

Design guarantees:
  * **Consistency** — the same entity maps to the same token throughout a prompt, so
    multi-row correlation is preserved (``IP_001`` in row 3 == ``IP_001`` in row 7).
  * **Reversibility** — ``restore()`` maps tokens back exactly; a redactor instance holds
    the per-call mapping.
  * **Type-preserving** — the token prefix tells the model the entity kind, which keeps
    its reasoning grounded without revealing the value.
  * **Non-destructive to analytics** — MITRE technique IDs (T1059), timestamps, ports and
    ordinary words are deliberately NOT redacted; they carry no tenant-identifying risk
    and the model needs them.

This is opt-in (the narrator only invokes it when configured) and has no effect on the
default local-LLM path, where data never leaves the host anyway.
"""
from __future__ import annotations

import re
from typing import Dict, Tuple

# Ordered most-specific-first so a broad pattern never bites a fragment of a longer one
# (an ARN contains ':' and '/', an email contains a host, an FQDN contains a short host).
_ARN_RE = re.compile(r"\barn:aws:[a-z0-9-]*:[a-z0-9-]*:\d*:[A-Za-z0-9:_/.\-]+")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_IPV6_RE = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b")
_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_FQDN_RE = re.compile(r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,30}[A-Za-z0-9])?\.){1,}[A-Za-z]{2,}\b")
_HOST_RE = re.compile(r"\b[A-Za-z]{2,4}-[A-Za-z0-9]{2,}-\d{1,4}\b")

# Never tokenize these — they are analytically essential and carry no tenant identity.
_MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
# Public infra suffixes we should NOT treat as sensitive FQDNs (avoid tokenizing
# amazonaws.com etc., which the model legitimately reasons about as cloud context).
_PUBLIC_FQDN_SUFFIXES = (
    "amazonaws.com", "windows.net", "microsoftonline.com", "googleapis.com",
    "office365.com", "azure.com", "cloudfront.net",
)


class IocRedactor:
    """Per-call reversible tokenizer. Create one instance per LLM request."""

    def __init__(self) -> None:
        self._counters: Dict[str, int] = {}
        self.token_to_value: Dict[str, str] = {}
        self._value_to_token: Dict[str, str] = {}

    def _token_for(self, kind: str, value: str) -> str:
        existing = self._value_to_token.get(value)
        if existing:
            return existing
        self._counters[kind] = self._counters.get(kind, 0) + 1
        token = f"{kind}_{self._counters[kind]:03d}"
        self.token_to_value[token] = value
        self._value_to_token[value] = token
        return token

    def _is_skippable(self, value: str) -> bool:
        if _MITRE_RE.match(value):
            return True
        low = value.lower()
        return any(low.endswith(suf) for suf in _PUBLIC_FQDN_SUFFIXES)

    def redact(self, text: str) -> str:
        """Return *text* with sensitive identifiers replaced by stable tokens."""
        if not text:
            return text

        def _sub(kind: str):
            def _repl(m: "re.Match[str]") -> str:
                v = m.group(0)
                if self._is_skippable(v):
                    return v
                return self._token_for(kind, v)
            return _repl

        # Order matters — longest/most-specific structures first.
        text = _ARN_RE.sub(_sub("ARN"), text)
        text = _EMAIL_RE.sub(_sub("USER"), text)
        text = _IPV6_RE.sub(_sub("IP"), text)
        text = _IPV4_RE.sub(_sub("IP"), text)
        text = _FQDN_RE.sub(_sub("HOST"), text)
        text = _HOST_RE.sub(_sub("HOST"), text)
        return text

    def restore(self, text: str) -> str:
        """Reverse :meth:`redact` — map every token back to its real value."""
        if not text:
            return text
        # Replace longer tokens first to avoid IP_1 colliding with IP_10 (zero-padded
        # tokens make this safe, but sort defensively anyway).
        for token in sorted(self.token_to_value, key=len, reverse=True):
            text = text.replace(token, self.token_to_value[token])
        return text

    @property
    def mapping(self) -> Dict[str, str]:
        return dict(self.token_to_value)


def redact(text: str) -> Tuple[str, IocRedactor]:
    """Convenience: tokenize *text*, returning (redacted, redactor_for_restore)."""
    r = IocRedactor()
    return r.redact(text), r
