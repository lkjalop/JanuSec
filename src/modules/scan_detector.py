from __future__ import annotations
import time
from collections import defaultdict, deque
from typing import Dict, Any

class ScanDetector:
    """Lightweight scan detector that tracks recent port activity per source.

    Emits simple attributes on detection: scan_type ('vertical'|'horizontal') and scan_score (0.0-1.0)
    """
    WINDOW = int(__import__('os').environ.get('PORTSCAN_WINDOW_SECONDS','300'))
    VERTICAL_THRESHOLD = int(__import__('os').environ.get('PORTSCAN_VERTICAL_THRESHOLD','20'))
    HORIZONTAL_THRESHOLD = int(__import__('os').environ.get('PORTSCAN_HORIZONTAL_THRESHOLD','30'))

    def __init__(self):
        self._vertical: Dict[str, set] = defaultdict(set)  # key src->dst -> set(ports)
        self._horizontal: Dict[str, set] = defaultdict(set)  # key src:port -> set(dst)
        self._last_ts: Dict[str, float] = {}

    def observe(self, src: str, dst: str, port: int, ts: float | None = None) -> Dict[str,Any]:
        now = ts or time.time()
        vkey = f"{src}->{dst}"
        hkey = f"{src}:{port}"
        self._vertical[vkey].add(port)
        self._horizontal[hkey].add(dst)
        self._last_ts[vkey] = now
        self._last_ts[hkey] = now
        # Prune stale keys
        stale = [k for k,t in self._last_ts.items() if now - t > self.WINDOW]
        for k in stale:
            self._last_ts.pop(k, None)
            self._vertical.pop(k, None)
            self._horizontal.pop(k, None)
        out = {'scan_type': None, 'scan_score': 0.0}
        if len(self._vertical.get(vkey, set())) >= self.VERTICAL_THRESHOLD:
            out['scan_type'] = 'vertical'
            out['scan_score'] = min(1.0, len(self._vertical[vkey]) / (self.VERTICAL_THRESHOLD * 1.0))
        if len(self._horizontal.get(hkey, set())) >= self.HORIZONTAL_THRESHOLD:
            # prefer horizontal label if both hit
            out['scan_type'] = 'horizontal'
            out['scan_score'] = max(out['scan_score'], min(1.0, len(self._horizontal[hkey]) / (self.HORIZONTAL_THRESHOLD * 1.0)))
        return out

__all__ = ['ScanDetector']
