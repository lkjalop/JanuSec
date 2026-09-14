from __future__ import annotations

import hashlib
from typing import Iterable, List, Tuple

GREASE_VALUES = {
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA,
}


def _filter_grease(seq: Iterable[int]) -> List[int]:
    return [int(x) for x in seq if int(x) not in GREASE_VALUES]


def _md5_hex(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def ja3_from_fields(version: int, ciphers: Iterable[int], extensions: Iterable[int], curves: Iterable[int], ec_point_formats: Iterable[int]) -> Tuple[str, str]:
    """Build JA3 string and hash from TLS ClientHello fields.

    JA3: SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    Lists are hyphen-joined, commas separate sections. GREASE values removed.
    """
    c = '-'.join(str(x) for x in _filter_grease(ciphers))
    e = '-'.join(str(x) for x in _filter_grease(extensions))
    ec = '-'.join(str(x) for x in _filter_grease(curves))
    pf = '-'.join(str(x) for x in ec_point_formats)
    s = f"{int(version)},{c},{e},{ec},{pf}"
    return s, _md5_hex(s)


def ja3s_from_fields(version: int, selected_cipher: int, extensions: Iterable[int]) -> Tuple[str, str]:
    """Build JA3S string and hash from TLS ServerHello fields.

    JA3S: SSLVersion,Cipher,Extensions
    """
    e = '-'.join(str(x) for x in _filter_grease(extensions))
    s = f"{int(version)},{int(selected_cipher)},{e}"
    return s, _md5_hex(s)


__all__ = ['ja3_from_fields', 'ja3s_from_fields', 'GREASE_VALUES']
