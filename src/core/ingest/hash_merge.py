from typing import Dict, Any


def merge_hashes(parser_hashes: Dict[str, str] | None, sidecar_hashes: Dict[str, str] | None) -> Dict[str, str]:
    """Merge two hash maps where sidecar values override parser values.

    - `parser_hashes`: hashes extracted by parser (may be None)
    - `sidecar_hashes`: hashes provided by sidecar JSON (may be None)

    Returns a new dict with keys like 'md5','sha1','sha256'. Sidecar takes precedence.
    """
    out: Dict[str, str] = {}
    if parser_hashes:
        for k, v in parser_hashes.items():
            if isinstance(k, str) and isinstance(v, str):
                out[k.lower()] = v.lower()
    if sidecar_hashes:
        for k, v in sidecar_hashes.items():
            if isinstance(k, str) and isinstance(v, str):
                out[k.lower()] = v.lower()
    return out


__all__ = ['merge_hashes']
