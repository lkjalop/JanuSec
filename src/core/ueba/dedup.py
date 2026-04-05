"""Simple dedup clustering utilities.

This provides a lightweight clusterer that groups similar alerts by hashed IOC sets
and a basic L2 distance on small numeric vectors.
"""
from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


def ioc_set_hash(iocs: set[str]) -> str:
    m = hashlib.sha256()
    for i in sorted(iocs):
        m.update(i.encode('utf-8'))
        m.update(b'|')
    return m.hexdigest()


def l2_distance(a: list[float], b: list[float]) -> float:
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b, strict=False)))


@dataclass
class Cluster:
    id: str
    members: list[str] = field(default_factory=list)
    ioc_hashes: set[str] = field(default_factory=set)
    vector_sum: list[float] = field(default_factory=list)
    count: int = 0

    def add(self, alert_id: str, ioc_hash: str, vec: list[float] | None = None):
        self.members.append(alert_id)
        self.ioc_hashes.add(ioc_hash)
        if vec is not None:
            if not self.vector_sum:
                self.vector_sum = vec.copy()
            else:
                for i, v in enumerate(vec):
                    if i < len(self.vector_sum):
                        self.vector_sum[i] += v
                    else:
                        self.vector_sum.append(v)
        self.count += 1

    def centroid(self) -> list[float]:
        if not self.vector_sum:
            return []
        return [v / max(1, self.count) for v in self.vector_sum]


class DedupClusterer:
    """Very small in-memory clusterer. Suitable for demo and local runs.

    For production, replace with a persistent store or Locality Sensitive Hashing index.
    """

    def __init__(self, vec_threshold: float = 1.0):
        self.clusters: dict[str, Cluster] = {}
        self.vec_threshold = vec_threshold

    def find_or_create(self, alert_id: str, iocs: set[str], vec: list[float] | None = None) -> str:
        ioch = ioc_set_hash(iocs)
        # exact ioc hash match -> same cluster
        for cid, c in self.clusters.items():
            if ioch in c.ioc_hashes:
                c.add(alert_id, ioch, vec)
                return cid
        # otherwise, try vector proximity
        if vec is not None:
            for cid, c in self.clusters.items():
                cent = c.centroid()
                if cent and l2_distance(cent, vec) <= self.vec_threshold:
                    c.add(alert_id, ioch, vec)
                    return cid
        # create new cluster
        cid = hashlib.sha1((alert_id + ioch).encode('utf-8')).hexdigest()[:12]
        c = Cluster(id=cid)
        c.add(alert_id, ioch, vec)
        self.clusters[cid] = c
        return cid
