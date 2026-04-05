"""TLS parsing helpers: extract ClientHello fields and compute JA3 string/md5.
Uses dpkt when available, falls back to a lightweight parser for ClientHello records.
"""
from __future__ import annotations
import hashlib
import logging
from typing import Tuple, Optional, List

logger = logging.getLogger(__name__)

def _md5_hex(s: str) -> str:
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def _assemble_ja3(version: int, ciphers: List[int], extensions: List[int], groups: List[int], sig_algs: List[int]) -> str:
    # Format: <version>,<cipher list>,<ext list>,<groups list>,<sig algs list>
    def list_to_str(lst: List[int]) -> str:
        return '-'.join(str(x) for x in lst)
    parts = [str(version), list_to_str(ciphers), list_to_str(extensions), list_to_str(groups), list_to_str(sig_algs)]
    return ','.join(parts)

def parse_tls_client_hello(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Return (sni, ja3_md5_or_none)."""
    # Try dpkt first for robustness
    try:
        import dpkt
        # dpkt's SSL/TLS parsing is limited across versions; try to find ClientHello by scanning
        try:
            from dpkt.ssl import TLSHandshake
        except Exception:
            TLSHandshake = None
        # dpkt may not expose high-level ClientHello helpers; fallback to byte scan
    except Exception:
        dpkt = None

    # naive parse: search for 0x16 (Handshake), then handshake type 0x01 (ClientHello)
    try:
        i = 0
        while i + 5 < len(payload):
            # TLS record header: type(1), version(2), length(2)
            rec_type = payload[i]
            if rec_type != 0x16:
                i += 1
                continue
            # handshake
            hs_type = payload[i+5] if i+5 < len(payload) else None
            if hs_type != 0x01:
                i += 1
                continue
            # Attempt to parse minimal ClientHello layout
            # Skip record header (5) + handshake header (4)
            hs_start = i + 5 + 4
            idx = hs_start
            # legacy_version (2)
            if idx + 2 > len(payload):
                break
            ver = int.from_bytes(payload[idx:idx+2], 'big')
            idx += 2
            # random (32)
            idx += 32
            if idx >= len(payload):
                break
            # session id
            sid_len = payload[idx]
            idx += 1 + sid_len
            if idx + 2 > len(payload):
                break
            # ciphers length
            ciphers_len = int.from_bytes(payload[idx:idx+2], 'big')
            idx += 2
            ciphers = []
            end_c = idx + ciphers_len
            while idx + 1 < end_c and idx + 2 <= len(payload):
                c = int.from_bytes(payload[idx:idx+2], 'big')
                ciphers.append(c)
                idx += 2
            # compression
            if idx >= len(payload):
                break
            comp_len = payload[idx]
            idx += 1 + comp_len
            if idx + 2 > len(payload):
                break
            # extensions
            ext_len = int.from_bytes(payload[idx:idx+2], 'big')
            idx += 2
            end_ext = idx + ext_len
            extensions = []
            groups = []
            sig_algs = []
            sni = None
            while idx + 4 <= end_ext and idx + 4 <= len(payload):
                ext_type = int.from_bytes(payload[idx:idx+2], 'big')
                ext_l = int.from_bytes(payload[idx+2:idx+4], 'big')
                idx += 4
                if idx + ext_l > len(payload):
                    break
                ext_data = payload[idx:idx+ext_l]
                if ext_type == 0x00:  # SNI
                    # parse SNI list
                    try:
                        # skip list length (2)
                        p = 2
                        if p + 3 <= len(ext_data):
                            name_type = ext_data[p]
                            name_len = int.from_bytes(ext_data[p+1:p+3], 'big')
                            sni = ext_data[p+3:p+3+name_len].decode('utf-8', errors='ignore')
                    except Exception:
                        pass
                elif ext_type == 0x0a:  # supported_groups
                    try:
                        gl = int.from_bytes(ext_data[0:2], 'big')
                        gi = 2
                        while gi + 1 < gl + 2 and gi + 1 < len(ext_data):
                            g = int.from_bytes(ext_data[gi:gi+2], 'big')
                            groups.append(g)
                            gi += 2
                    except Exception:
                        pass
                elif ext_type == 0x0d:  # signature_algorithms
                    try:
                        sl = int.from_bytes(ext_data[0:2], 'big')
                        si = 2
                        while si + 1 < sl + 2 and si + 1 < len(ext_data):
                            sa = int.from_bytes(ext_data[si:si+2], 'big')
                            sig_algs.append(sa)
                            si += 2
                    except Exception:
                        pass
                # record extension type
                extensions.append(ext_type)
                idx += ext_l
            ja3 = _assemble_ja3(ver, ciphers, extensions, groups, sig_algs)
            ja4 = None
            return sni, _md5_hex(ja3), ja4
        return None, None, None
    except Exception:
        return None, None, None
