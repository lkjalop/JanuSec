from __future__ import annotations

import math
from typing import Iterable

def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy in bits per character for a string.
    Returns 0.0 for empty input.
    """
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    entropy = 0.0
    for c in freq.values():
        p = c / length
        entropy -= p * math.log2(p)
    return entropy

def max_entropy(strings: Iterable[str]) -> float:
    m = 0.0
    for s in strings:
        if not s:
            continue
        e = shannon_entropy(s)
        if e > m:
            m = e
    return m
