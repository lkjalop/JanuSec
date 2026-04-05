"""Detect high-entropy files and large exfil transfers.

Provides two factors: `file_high_entropy` (when file content entropy exceeds threshold)
and `data_exfil_size_large` when aggregate bytes transferred for a batch exceed threshold.
"""
from typing import Any, Dict, List
import math

def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b,0)+1
    ent = 0.0
    l = len(data)
    for v in freq.values():
        p = v / l
        ent -= p * math.log2(p)
    return ent

def detect_entropy_and_exfil(runtime: Any, files: List[Dict[str,Any]] = None, exfil_threshold: int = 1048576, entropy_threshold: float = 7.0) -> List[Dict[str,Any]]:
    results: List[Dict[str,Any]] = []
    if runtime is None and files is None:
        return results
    # Inspect files list if provided or runtime.recent_files
    try:
        if files is None:
            files = getattr(runtime, 'recent_files', []) or []
    except Exception:
        files = files or []
    # File entropy checks
    for f in (files or []):
        try:
            content = None
            if isinstance(f.get('content'), (bytes, bytearray)):
                content = bytes(f.get('content'))
            elif isinstance(f.get('raw'), (bytes, bytearray)):
                content = bytes(f.get('raw'))
            elif f.get('sample') and isinstance(f.get('sample'), str):
                try:
                    content = bytes(f.get('sample'), 'utf-8')
                except Exception:
                    content = None
            if content:
                ent = _shannon_entropy(content)
                if ent >= entropy_threshold:
                    results.append({'factor':'file_high_entropy','sha256':f.get('sha256'),'entropy':round(ent,3),'score':0.7,'reason':'high entropy file sample','metadata':{'mitre':['T1005'],'stride':['data_leak']}})
        except Exception:
            pass

    # Exfil size: runtime may expose out_bytes_per_batch or similar
    try:
        exfil = 0
        # attempt multiple common runtime attrs
        if hasattr(runtime, 'out_bytes'):
            exfil = sum(getattr(runtime, 'out_bytes') or [])
        elif hasattr(runtime, 'out_bytes_per_batch'):
            exfil = sum(getattr(runtime, 'out_bytes_per_batch') or [])
        elif hasattr(runtime, 'recent_out_bytes'):
            exfil = sum(getattr(runtime, 'recent_out_bytes') or [])
        # fallback to scanning session file records if provided
        if exfil and exfil >= exfil_threshold:
            results.append({'factor':'data_exfil_size_large','bytes':int(exfil),'score':0.6,'reason':f'aggregate exfil {int(exfil)} bytes exceeds threshold','metadata':{'mitre':['T1041'],'stride':['privacy']}})
    except Exception:
        pass
    return results
