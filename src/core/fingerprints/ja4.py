from __future__ import annotations

import hashlib
from typing import Iterable, Tuple


def _md5_hex(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def ja4_from_tls_http(version: int, cipher_count: int, ext_count: int, ua: str | None = None) -> Tuple[str, str]:
    """Approximate JA4/JA4S-like canonicalization using TLS and optional UA.

    This is not the full JA4 spec. It creates a stable string with a subset of
    features commonly available: TLS version, counts of ciphers/extensions, and
    a weak UA hash (if provided). Returns (string, md5 hash).
    """
    ua_hash = hashlib.md5((ua or '').strip().lower().encode()).hexdigest()[:8] if ua else ''
    s = f"v{int(version)}-c{int(cipher_count)}-e{int(ext_count)}-u{ua_hash}"
    return s, _md5_hex(s)


__all__ = ['ja4_from_tls_http']
