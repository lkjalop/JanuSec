"""Geo-Velocity Tracking Service

Tracks last (lat, lon, timestamp) per entity (user) and computes travel speed.
Emits anomaly if computed km/h exceeds threshold.
"""
from __future__ import annotations
import math, time, asyncio, os
from dataclasses import dataclass
from typing import Dict, Tuple, Optional, Any

try:  # pragma: no cover
    from prometheus_client import Counter, Gauge, Histogram  # type: ignore
except Exception:  # pragma: no cover
    class _MetricShim:
        """No-op metric shim when prometheus_client is missing."""

        def __init__(self,*_a,**_k) -> None:
            pass
        def labels(self,*_a,**_k):
            return self
        def inc(self,*_a,**_k) -> None:
            return None
        def observe(self,*_a,**_k) -> None:
            return None
        def set(self,*_a,**_k) -> None:
            return None

    Counter = Gauge = Histogram = _MetricShim  # type: ignore

_GEO_SPEED_THRESHOLD = float(os.getenv('GEO_VELOCITY_MAX_KMH','900') or 900)  # commercial jet upper bound
_GEO_MIN_DISTANCE_KM = float(os.getenv('GEO_VELOCITY_MIN_DISTANCE_KM','50') or 50)
_GEO_MIN_TIME_DELTA_S = float(os.getenv('GEO_VELOCITY_MIN_TIME_DELTA_S','300') or 300)

_geo_updates_total = Counter('geo_velocity_updates_total','Updates of geo velocity state',['entity_type'])
_geo_anomalies_total = Counter('geo_velocity_anomalies_total','Geo velocity anomalies',['entity_type'])
_geo_last_speed = Gauge('geo_velocity_last_speed_kmh','Last computed speed km/h',['entity_type'])

@dataclass
class GeoPoint:
    lat: float
    lon: float
    ts: float

class GeoVelocityService:
    def __init__(self):
        self._store: Dict[Tuple[str,str], GeoPoint] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        R = 6371.0
        dlat = math.radians(lat2-lat1)
        dlon = math.radians(lon2-lon1)
        a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1))*math.cos(math.radians(lat2))*math.sin(dlon/2)**2
        c = 2*math.atan2(math.sqrt(a), math.sqrt(1-a))
        return R*c

    async def update(self, entity_type: str, entity_id: str, lat: float, lon: float, ts: float | None = None) -> dict[str,Any]:
        now = ts or time.time()
        key = (entity_type, entity_id)
        async with self._lock:
            prev = self._store.get(key)
            self._store[key] = GeoPoint(lat, lon, now)
            try: _geo_updates_total.labels(entity_type=entity_type).inc()
            except Exception: pass
        if prev is None:
            return {'speed_kmh': 0.0, 'anomaly': False}
        dt = now - prev.ts
        if dt <= 0 or dt < _GEO_MIN_TIME_DELTA_S:
            return {'speed_kmh': 0.0, 'anomaly': False}
        dist_km = self._haversine(prev.lat, prev.lon, lat, lon)
        if dist_km < _GEO_MIN_DISTANCE_KM:
            return {'speed_kmh': 0.0, 'anomaly': False}
        speed_kmh = (dist_km / (dt/3600.0)) if dt > 0 else 0.0
        try: _geo_last_speed.labels(entity_type=entity_type).set(speed_kmh)
        except Exception: pass
        anomaly = speed_kmh > _GEO_SPEED_THRESHOLD
        if anomaly:
            try: _geo_anomalies_total.labels(entity_type=entity_type).inc()
            except Exception: pass
        return {'speed_kmh': speed_kmh, 'anomaly': anomaly, 'distance_km': dist_km, 'delta_seconds': dt}

GEO_VELOCITY = GeoVelocityService()

__all__ = ['GEO_VELOCITY']
