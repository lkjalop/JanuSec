"""Geo-velocity calculations and helper for impossible travel detection."""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class LocationSample:
    lat: float
    lon: float
    ts: float  # epoch seconds


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    r = 6371.0
    h = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    return 2 * r * math.asin(math.sqrt(h))


class GeoVelocity:
    """Track last-known sample per entity and compute km/h and explanatory string."""

    def __init__(self):
        self._last: dict[str, LocationSample] = {}

    def update_and_compute(self, entity: str, lat: float, lon: float, ts: float) -> dict | None:
        prev = self._last.get(entity)
        curr = LocationSample(lat=lat, lon=lon, ts=ts)
        self._last[entity] = curr
        if prev is None:
            return None
        # compute distance
        dist = haversine_km((prev.lat, prev.lon), (curr.lat, curr.lon))
        dt = max(1e-6, curr.ts - prev.ts)
        kmh = (dist / dt) * 3600.0
        explanation = f"{dist:.1f} km in {int(dt)}s => {kmh:.1f} km/h ({prev.lat:.4f},{prev.lon:.4f} -> {curr.lat:.4f},{curr.lon:.4f})"
        return {"kmh": kmh, "distance_km": dist, "seconds": dt, "explanation": explanation}
