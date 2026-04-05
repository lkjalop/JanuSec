from __future__ import annotations

import math
import json
import os
from collections import defaultdict
from typing import Dict, Iterable, Optional
from pathlib import Path


class TfidfProfile:
    """Lightweight incremental TF-IDF-ish profile with persistence and decay.

    - Maintain document frequency (DF) per token and total documents (N)
    - add_document(tokens): counts doc-level membership and persists state
    - get_rarity_score(tokens): returns max token IDF-like score normalized to 0..1
    - decay(factor): multiply DF and N by factor (floating decay)
    - evict(max_terms): evict lowest-frequency terms when exceeding capacity
    """

    def __init__(self):
        self._df: Dict[str, float] = defaultdict(float)
        self._N: float = 0.0

    def add_document(self, tokens: Iterable[str]) -> None:
        seen = set(tokens)
        if not seen:
            return
        self._N += 1.0
        for t in seen:
            self._df[t] = self._df.get(t, 0.0) + 1.0

    def get_rarity_score(self, tokens: Iterable[str]) -> float:
        """Compute a 0..1 rarity score: higher = rarer.
        Uses idf = log((N+1)/(df+1)) + 1, then normalize by log(N+1)+1
        """
        if self._N == 0:
            return 0.0
        max_idf = 0.0
        denom = math.log(self._N + 1.0) + 1.0
        for t in tokens:
            df = int(self._df.get(t, 0.0))
            idf = math.log((self._N + 1.0) / (df + 1.0)) + 1.0
            if idf > max_idf:
                max_idf = idf
        score = max_idf / denom if denom > 0 else 0.0
        return float(max(0.0, min(1.0, score)))

    def decay(self, factor: float = 0.9) -> None:
        """Apply exponential decay to counts. Factor in (0,1]."""
        if factor >= 1.0 or factor <= 0.0:
            return
        self._N = self._N * factor
        for k in list(self._df.keys()):
            self._df[k] = self._df[k] * factor
            if self._df[k] < 1e-6:
                del self._df[k]

    def evict(self, max_terms: int = 5000) -> None:
        """Evict least-frequent terms until under max_terms."""
        if len(self._df) <= max_terms:
            return
        # sort tokens by df ascending and drop lowest
        items = sorted(self._df.items(), key=lambda it: it[1])
        to_drop = len(self._df) - max_terms
        for i in range(to_drop):
            k = items[i][0]
            del self._df[k]

    def to_dict(self) -> Dict:
        return {'N': self._N, 'df': dict(self._df)}

    @classmethod
    def from_dict(cls, d: Dict) -> 'TfidfProfile':
        p = cls()
        p._N = float(d.get('N', 0.0))
        for k, v in d.get('df', {}).items():
            p._df[k] = float(v)
        return p


class TfidfManager:
    """Manages per-tenant TfidfProfile instances with on-disk persistence."""

    BASE_DIR = Path(os.getenv('TFIDF_STORE', 'data/tfidf'))
    DEFAULT_MAX_TERMS = int(os.getenv('TFIDF_MAX_TERMS', '5000'))
    DEFAULT_DECAY = float(os.getenv('TFIDF_DECAY_FACTOR', '0.95'))

    def __init__(self):
        self._profiles: Dict[str, TfidfProfile] = {}
        self.BASE_DIR.mkdir(parents=True, exist_ok=True)

    def _path_for(self, tenant: str) -> Path:
        t = (tenant or 'default').replace('/', '_')
        return self.BASE_DIR / f"{t}.json"

    def get(self, tenant: Optional[str]) -> TfidfProfile:
        t = tenant or 'default'
        if t not in self._profiles:
            p = TfidfProfile()
            path = self._path_for(t)
            if path.exists():
                try:
                    with path.open('r', encoding='utf-8') as f:
                        data = json.load(f)
                        p = TfidfProfile.from_dict(data)
                except Exception:
                    p = TfidfProfile()
            self._profiles[t] = p
        return self._profiles[t]

    def save(self, tenant: Optional[str]) -> None:
        t = tenant or 'default'
        p = self._profiles.get(t)
        if not p:
            return
        path = self._path_for(t)
        try:
            with path.open('w', encoding='utf-8') as f:
                json.dump(p.to_dict(), f)
        except Exception:
            pass

    def decay_and_persist_all(self, decay_factor: Optional[float] = None, max_terms: Optional[int] = None) -> None:
        # Allow runtime overrides via env or parameters so tests can monkeypatch env before call
        df = decay_factor if decay_factor is not None else float(os.getenv('TFIDF_DECAY_FACTOR', str(self.DEFAULT_DECAY)))
        mt = max_terms if max_terms is not None else int(os.getenv('TFIDF_MAX_TERMS', str(self.DEFAULT_MAX_TERMS)))
        for t, p in list(self._profiles.items()):
            p.decay(df)
            p.evict(mt)
            self.save(t)


GLOBAL_TFIDF_MANAGER = TfidfManager()
# Backwards compatibility alias (some tests / modules import GLOBAL_TFIDF)
GLOBAL_TFIDF = GLOBAL_TFIDF_MANAGER
