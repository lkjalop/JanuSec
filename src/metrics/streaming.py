from __future__ import annotations

"""Lightweight streaming detectors and sketches.

All structures are memory-bounded and O(1)–O(log n) per update.

APIs (intended usage):
 - ewma.update(key, x) -> float
 - cusum.update(key, x) -> dict {alarm: bool, dir: int, s_pos: float, s_neg: float}
 - hw.update(key, x, season=24) -> dict {forecast: float, residual: float, z: float}
 - pq.update(key, x) -> dict of quantiles when queried
 - cms.add(key, count=1) / cms.estimate(key) -> float
 - hll.add(key) / hll.count() -> int
 - bloom.add(key) / bloom.maybe_present(key) -> bool
 - rarity.update(key, bucket_ts) -> bool (True if first-seen within TTL)
"""

import math
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple


# ---- Simple hash helpers (deterministic, low-overhead) ----

def _hash64(x: str, seed: int = 0x9E3779B97F4A7C15) -> int:
    h = seed
    for ch in x:
        h ^= ord(ch)
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


# ---- EWMA ----

class EWMA:
    def __init__(self, alpha: float = 0.2):
        self.alpha = max(0.0001, min(1.0, float(alpha)))
        self.state: Dict[str, float] = {}

    def update(self, key: str, x: float) -> float:
        prev = self.state.get(key)
        if prev is None:
            v = float(x)
        else:
            a = self.alpha
            v = a * float(x) + (1.0 - a) * prev
        self.state[key] = v
        return v


# ---- CUSUM (Page-Hinkley-like) ----

class CUSUM:
    def __init__(self, drift: float = 0.0, threshold: float = 5.0, alpha_mean: float = 0.1):
        self.drift = float(drift)
        self.threshold = max(0.001, float(threshold))
        self.mean = EWMA(alpha_mean)
        self.s_pos: Dict[str, float] = {}
        self.s_neg: Dict[str, float] = {}

    def update(self, key: str, x: float) -> Dict[str, Any]:
        m = self.mean.update(key, x)
        xp = float(x) - m - self.drift
        xn = m - float(x) - self.drift
        s_p = max(0.0, self.s_pos.get(key, 0.0) + xp)
        s_n = max(0.0, self.s_neg.get(key, 0.0) + xn)
        self.s_pos[key] = s_p
        self.s_neg[key] = s_n
        alarm = s_p > self.threshold or s_n > self.threshold
        direction = 1 if s_p > s_n else (-1 if s_n > s_p else 0)
        if alarm:
            # Light reset to avoid repeated alarms
            self.s_pos[key] *= 0.25
            self.s_neg[key] *= 0.25
        return {'alarm': alarm, 'dir': direction, 's_pos': s_p, 's_neg': s_n, 'mean': m}


# ---- Holt-Winters Lite (additive) ----

@dataclass
class _HWState:
    level: float
    trend: float
    season: List[float]
    last_ts: float
    mean_resid: float = 0.0
    var_resid: float = 1.0


class HoltWintersLite:
    def __init__(self, alpha: float = 0.2, beta: float = 0.01, gamma: float = 0.2, season_length: int = 24):
        self.alpha = max(0.0001, min(1.0, float(alpha)))
        self.beta = max(0.0001, min(1.0, float(beta)))
        self.gamma = max(0.0001, min(1.0, float(gamma)))
        self.season_length = max(2, int(season_length))
        self.state: Dict[str, _HWState] = {}

    def update(self, key: str, x: float, season: int | None = None) -> Dict[str, float]:
        L = season or self.season_length
        st = self.state.get(key)
        if st is None:
            init = float(x)
            st = _HWState(level=init, trend=0.0, season=[0.0] * L, last_ts=time.time())
        # Forecast using previous state
        idx = int(time.time()) % L
        season_val = st.season[idx]
        forecast = st.level + st.trend + season_val
        # Update components (additive)
        x = float(x)
        last_level = st.level
        st.level = self.alpha * (x - season_val) + (1 - self.alpha) * (st.level + st.trend)
        st.trend = self.beta * (st.level - last_level) + (1 - self.beta) * st.trend
        st.season[idx] = self.gamma * (x - st.level) + (1 - self.gamma) * season_val
        st.last_ts = time.time()
        # Residual + EWMA variance estimate (z-score approximation)
        resid = x - forecast
        st.mean_resid = 0.9 * st.mean_resid + 0.1 * resid
        st.var_resid = 0.9 * st.var_resid + 0.1 * (resid - st.mean_resid) ** 2
        std = math.sqrt(max(1e-6, st.var_resid))
        z = (resid - st.mean_resid) / std if std > 0 else 0.0
        self.state[key] = st
        return {'forecast': forecast, 'residual': resid, 'z': z}


# ---- Simple P2 quantile estimator for p50/p95 ----

class P2Quantiles:
    def __init__(self, qs: List[float] | None = None):
        self.qs = qs or [0.5, 0.95]
        self.state: Dict[str, Dict[float, float]] = {}
        self.ewma_counts: Dict[str, float] = {}

    def update(self, key: str, x: float) -> Dict[float, float]:
        # For simplicity and stability, track EWMA per quantile rather than full P2 markers
        # This is not exact quantiles but behaves like adaptive thresholds.
        st = self.state.setdefault(key, {})
        self.ewma_counts[key] = self.ewma_counts.get(key, 0.0) + 1.0
        for q in self.qs:
            # Move target toward x based on whether x is above/below current estimate
            v = st.get(q, float(x))
            step = 0.05  # small adaptation step
            if x > v:
                v = v + step * (1.0 - q) * (x - v)
            else:
                v = v - step * q * (v - x)
            st[q] = v
        return st


# ---- Count-Min Sketch ----

class CountMinSketch:
    def __init__(self, width: int = 1024, depth: int = 4, seed: int = 0xC0FFEE):
        self.w = max(16, int(width))
        self.d = max(1, int(depth))
        self.seed = int(seed)
        self.tables: List[List[float]] = [[0.0] * self.w for _ in range(self.d)]

    def _hashes(self, key: str) -> List[int]:
        hs = []
        for i in range(self.d):
            h = _hash64(f"{self.seed+i}:{key}") % self.w
            hs.append(h)
        return hs

    def add(self, key: str, count: float = 1.0) -> None:
        for r, c in zip(self.tables, self._hashes(key)):
            r[c] += float(count)

    def estimate(self, key: str) -> float:
        return min(self.tables[i][h] for i, h in enumerate(self._hashes(key)))


# ---- HyperLogLog (approximate distinct counter) ----

class HyperLogLog:
    def __init__(self, b: int = 6, seed: int = 0xBADC0DE):
        # m = 2^b registers
        self.b = max(4, min(16, int(b)))
        self.m = 1 << self.b
        self.seed = int(seed)
        self.M = [0] * self.m

    def add(self, key: str) -> None:
        x = _hash64(f"{self.seed}:{key}") & 0xFFFFFFFFFFFFFFFF
        j = x >> (64 - self.b)
        w = (x << self.b) & 0xFFFFFFFFFFFFFFFF
        # rho = position of the first 1 bit in w (1-indexed)
        rank = 1
        while w & (1 << 63) == 0 and rank <= (64 - self.b):
            rank += 1
            w = (w << 1) & 0xFFFFFFFFFFFFFFFF
        self.M[j] = max(self.M[j], rank)

    def count(self) -> int:
        m = float(self.m)
        Z = sum((2.0 ** -v) for v in self.M)
        if Z == 0:
            return 0
        alpha = {
            16: 0.673,
            32: 0.697,
            64: 0.709,
        }.get(self.m, 0.7213 / (1 + 1.079 / m))
        E = alpha * (m * m) / Z
        # Small-range correction
        if E <= 5 / 2 * m:
            V = sum(1 for v in self.M if v == 0)
            if V > 0:
                E = m * math.log(m / V)
        return int(E)


# ---- Bloom Filter ----

class Bloom:
    def __init__(self, m_bits: int = 8192, k_hashes: int = 4, seed: int = 0xA11CE):
        self.m = max(256, int(m_bits))
        self.k = max(1, int(k_hashes))
        self.seed = int(seed)
        self.bits = bytearray(self.m // 8 + 1)

    def _indexes(self, key: str) -> List[int]:
        idxs = []
        for i in range(self.k):
            h = _hash64(f"{self.seed+i}:{key}") % self.m
            idxs.append(int(h))
        return idxs

    def add(self, key: str) -> None:
        for idx in self._indexes(key):
            byte_i = idx // 8
            bit_i = idx % 8
            self.bits[byte_i] |= (1 << bit_i)

    def maybe_present(self, key: str) -> bool:
        for idx in self._indexes(key):
            byte_i = idx // 8
            bit_i = idx % 8
            if (self.bits[byte_i] & (1 << bit_i)) == 0:
                return False
        return True


# ---- Rolling rarity (first-seen TTL) ----

class FirstSeenTTL:
    def __init__(self, ttl_seconds: int = 86400):
        self.ttl = max(1, int(ttl_seconds))
        self.last_seen: Dict[str, float] = {}

    def update(self, key: str, now: float | None = None) -> bool:
        t = now if isinstance(now, (int, float)) else time.time()
        prev = self.last_seen.get(key)
        self.last_seen[key] = t
        if prev is None:
            return True
        return (t - prev) >= self.ttl


# ---- Module-level singletons (opt-in) ----

EWMA_DEFAULT = EWMA(alpha=0.2)
CUSUM_DEFAULT = CUSUM(drift=0.0, threshold=5.0, alpha_mean=0.1)
HW_DEFAULT = HoltWintersLite(alpha=0.2, beta=0.01, gamma=0.2, season_length=24)
P2_DEFAULT = P2Quantiles(qs=[0.5, 0.95])
CMS_DEFAULT = CountMinSketch(width=2048, depth=4)
HLL_DEFAULT = HyperLogLog(b=6)
BLOOM_BENIGN = Bloom(m_bits=16384, k_hashes=4)
RARITY_DAILY = FirstSeenTTL(ttl_seconds=86400)


__all__ = [
    'EWMA', 'CUSUM', 'HoltWintersLite', 'P2Quantiles',
    'CountMinSketch', 'HyperLogLog', 'Bloom', 'FirstSeenTTL',
    'EWMA_DEFAULT', 'CUSUM_DEFAULT', 'HW_DEFAULT', 'P2_DEFAULT',
    'CMS_DEFAULT', 'HLL_DEFAULT', 'BLOOM_BENIGN', 'RARITY_DAILY'
]

