"""SMB extractor placeholder.
Attempts to locate SMB file transfer patterns and extract basic metadata (filenames, sizes, hashes).
This is a conservative stub — production-grade SMB parsing should use impacket or similar.
"""
from __future__ import annotations
import hashlib
from typing import Dict, Any, Optional

def extract_files_from_flow(flow: Dict[str, Any]) -> list[Dict[str, Any]]:
    """Return list of extracted file metadata dicts with keys: filename, sha256, size.
    If none found, return empty list.
    """
    out = []
    try:
        # Prefer explicit file_transfer metadata previously extracted
        if isinstance(flow.get('file_transfer'), list):
            for f in flow.get('file_transfer'):
                if isinstance(f, dict):
                    fname = f.get('filename') or f.get('name')
                    data = f.get('data')
                    if data and isinstance(data, (bytes, bytearray)):
                        # Only hash small blobs to avoid OOM
                        sample = data if len(data) <= 1024 * 64 else data[:1024]
                        sha = hashlib.sha256(sample).hexdigest()
                        out.append({'filename': fname, 'sha256': sha, 'size': len(data)})
            return out

        # If impacket is available, attempt to parse SMB2 file data units
        try:
            from impacket.smb import SMB2  # type: ignore
            # impacket parsing from raw TCP payloads is non-trivial; look for 'SMB' signature in payloads
            payloads = flow.get('payloads') or ([flow.get('payload')] if flow.get('payload') else [])
            for p in payloads:
                if not isinstance(p, (bytes, bytearray)):
                    continue
                if b'SMB2' in p[:8] or p.startswith(b'\xfeSMB'):
                    # crude: hash the whole SMB payload header + small window
                    sample = p[:4096]
                    sha = hashlib.sha256(sample).hexdigest()
                    out.append({'filename': None, 'sha256': sha, 'size': len(p)})
        except Exception:
            # fallback: heuristic blob extraction from payloads
            if isinstance(flow.get('payloads'), list):
                for p in flow.get('payloads'):
                    if isinstance(p, (bytes, bytearray)) and len(p) > 200:
                        sample = p[:1024]
                        sha = hashlib.sha256(sample).hexdigest()
                        out.append({'filename': None, 'sha256': sha, 'size': len(p)})
    except Exception:
        pass
    return out
