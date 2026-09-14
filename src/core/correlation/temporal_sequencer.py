from __future__ import annotations
import json, time, os
from pathlib import Path
from typing import List, Dict, Any, Tuple
try:  # metrics optional
    from .metrics_correlation import inc_temporal  # type: ignore
except Exception:  # pragma: no cover
    def inc_temporal(_p: str):
        return None
try:  # persistence optional
    from .correlation_state_store import flush_state  # type: ignore
except Exception:  # pragma: no cover
    def flush_state(*_a, **_k):
        return None

_PATTERN_PATH = os.getenv("TEMPORAL_PATTERNS_PATH", "src/config/temporal_patterns.json")

class TemporalSequencer:
    def __init__(self, path: str = _PATTERN_PATH):
        self.path = path
        self.patterns: List[Dict[str, Any]] = []
        self._load()
        # Per entity buffer: entity_id -> list[(ts, factor)]
        self.buffers: Dict[str, List[Tuple[float, str]]] = {}
        self.max_buffer = 256

    def _load(self):
        try:
            p = Path(self.path)
            if not p.exists():
                return
            data = json.loads(p.read_text(encoding="utf-8"))
            self.patterns = list(data.get("patterns", []))
        except Exception:
            pass

    def record(self, entity_id: str, factors: List[str]):
        now = time.time()
        buf = self.buffers.setdefault(entity_id, [])
        for f in factors:
            buf.append((now, f))
        if len(buf) > self.max_buffer:
            del buf[:len(buf)-self.max_buffer]

    def detect(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        now = time.time()
        for pat in self.patterns:
            seq = pat.get("sequence", [])
            span = float(pat.get("max_span_seconds", 3600))
            for entity, buf in self.buffers.items():
                # Simple ordered subsequence within span
                idx = 0
                first_ts = None
                for (ts, fac) in buf:
                    if fac == seq[idx]:
                        if idx == 0:
                            first_ts = ts
                        idx += 1
                        if idx >= len(seq):
                            if first_ts and (ts - first_ts) <= span:
                                name = pat.get("name") or "unknown"
                                findings.append({"entity": entity, "pattern": name, "factors": seq, "span_seconds": ts - first_ts})
                                inc_temporal(name)
                            break
                # truncate stale entries
                cutoff = now - span*2
                self.buffers[entity] = [e for e in buf if e[0] >= cutoff]
        # best-effort persistence flush (co-occurrence merged upstream)
        try:
            from .cooccurrence import GLOBAL_COOCCURRENCE  # type: ignore
            flush_state(getattr(GLOBAL_COOCCURRENCE, 'pairs', {}), self.buffers)
        except Exception:
            pass
        return findings

GLOBAL_TEMPORAL_SEQUENCER = TemporalSequencer()

__all__ = ["TemporalSequencer", "GLOBAL_TEMPORAL_SEQUENCER"]
