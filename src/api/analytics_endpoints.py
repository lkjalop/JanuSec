from __future__ import annotations

"""Analytics endpoints — real data from in-memory pipeline stores.

Endpoints:
 - GET /api/v1/analytics/clusters    : Factor-signature groupings across decisions
 - GET /api/v1/analytics/mitre       : Aggregated MITRE technique frequency
 - GET /api/v1/analytics/timeline    : Chronological mixed event stream
 - GET /api/v1/analytics/heavy_hitters: Top domains/IPs by freq (Count-Min Sketch)
 - GET /api/v1/analytics/dread_distribution: DREAD composite histogram + dim averages
 - GET /api/v1/analytics/top_actors  : Top source IPs, users, hosts by alert volume
"""
import collections
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, Query, Request

try:
    from .runtime_state import DECISION_CACHE  # type: ignore
except Exception:  # pragma: no cover
    DECISION_CACHE = {}

from .dependencies import get_canonical_alert_ring
from .tenant_helpers import resolve_tenant_id

router = APIRouter(tags=["Analytics"])

# --------------- Helper utilities ---------------

def _iter_decisions(limit: int = 1000):
    values = list(DECISION_CACHE.values())[-limit:]
    yield from values

# Basic fuzzy command-line similarity placeholder (length bucket + prefix)

def _decision_signature(dec) -> str:
    fid = getattr(dec, 'event_id', None) or 'unknown'
    factors = getattr(dec, 'factors', []) or []
    # create a coarse signature using sorted truncated factors
    norm = sorted([str(f)[:12].lower() for f in factors if isinstance(f, str)])
    bucket = len(norm)
    return f"b{bucket}:{'-'.join(norm[:3])}" if norm else f"b0:{fid[:6]}"

# --------------- /clusters ---------------
@router.get('/api/v1/analytics/clusters')
async def analytics_clusters(
    limit: int = Query(250, le=1000),
    min_size: int = Query(2, ge=1),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(request, tenant_id)
    clusters: dict[str, list[dict[str, Any]]] = {}
    for dec in _iter_decisions(limit=limit):
        if tenant_id and getattr(dec, 'tenant_id', None) != tenant_id:
            continue
        sig = _decision_signature(dec)
        clusters.setdefault(sig, []).append({
            'event_id': getattr(dec, 'event_id', None),
            'verdict': getattr(dec, 'verdict', None),
            'confidence': getattr(dec, 'confidence', None),
            'factors': list(getattr(dec, 'factors', []) or [])[:10],
        })
    resp = []
    for sig, members in clusters.items():
        if len(members) < min_size:
            continue
        confidences = [m.get('confidence') or 0.0 for m in members]
        avg_conf = round(sum(confidences)/len(confidences), 3) if confidences else 0.0
        resp.append({
            'signature': sig,
            'size': len(members),
            'avg_confidence': avg_conf,
            'sample_members': members[:5],
        })
    resp.sort(key=lambda r: (-r['size'], -r['avg_confidence']))
    return {
        'tenant_id': tenant_id,
        'generated_at': time.time(),
        'clusters': resp,
        'meta': {'limit': limit, 'min_size': min_size}
    }

# --------------- /mitre ---------------
@router.get('/api/v1/analytics/mitre')
async def analytics_mitre(
    limit: int = Query(800, le=2000),
    top_n: int = Query(25, le=100),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(request, tenant_id)
    counts: dict[str, int] = {}
    for dec in _iter_decisions(limit=limit):
        if tenant_id and getattr(dec, 'tenant_id', None) != tenant_id:
            continue
        factors = getattr(dec, 'factors', []) or []
        for f in factors:
            if isinstance(f, str) and f.startswith('T') and len(f) <= 8:
                counts[f] = counts.get(f, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_n]
    return {
        'tenant_id': tenant_id,
        'generated_at': time.time(),
        'techniques': [ {'technique': t, 'count': c} for t,c in ranked ],
        'meta': {'limit': limit, 'top_n': top_n}
    }

# --------------- /timeline ---------------
@router.get('/api/v1/analytics/timeline')
async def analytics_timeline(
    limit_decisions: int = Query(200, le=1000),
    limit_alerts: int = Query(200, le=1000),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> dict[str, Any]:
    tenant_id = resolve_tenant_id(request, tenant_id)
    # Extract recent decisions
    timeline: list[dict[str, Any]] = []
    decisions_list = list(DECISION_CACHE.values())[-limit_decisions:]
    decision_count = 0
    for d in decisions_list:
        if tenant_id and getattr(d, 'tenant_id', None) != tenant_id:
            continue
        decision_count += 1
        ts = getattr(d, 'ts', None) or getattr(d, 'timestamp', None) or None
        timeline.append({
            'ts': ts,
            'type': 'decision',
            'event_id': getattr(d, 'event_id', None),
            'verdict': getattr(d, 'verdict', None),
            'confidence': getattr(d, 'confidence', None),
        })
    # Extract recent alerts
    try:
        ring, ring_lock, _ = get_canonical_alert_ring()
        with ring_lock:
            alerts = list(ring)[-limit_alerts:]
    except Exception:
        alerts = []
    alert_count = 0
    for a in alerts:
        if tenant_id and a.get('tenant_id') != tenant_id:
            continue
        alert_count += 1
        timeline.append({
            'ts': a.get('ts'),
            'type': 'alert',
            'id': a.get('id'),
            'verdict': a.get('verdict'),
            'score': a.get('score'),
            'tenant_id': a.get('tenant_id'),
        })
    # Sort by timestamp if available, descending
    timeline.sort(key=lambda x: x.get('ts') or 0, reverse=True)
    return {
        'tenant_id': tenant_id,
        'generated_at': time.time(),
        'items': timeline,
        'counts': {'decisions': decision_count, 'alerts': min(alert_count, limit_alerts)},
        'meta': {'limit_decisions': limit_decisions, 'limit_alerts': limit_alerts}
    }


# --------------- /heavy_hitters (debug) ---------------
@router.get('/api/v1/analytics/heavy_hitters')
async def analytics_heavy_hitters(
    top_n: int = Query(25, le=200),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> dict[str, Any]:
    """Approximate heavy hitters using Count-Min Sketch over known candidates.

    Candidates are drawn from the DomainTracker's first-seen maps to avoid
    maintaining a separate candidate heap. Results are approximate and best-effort.
    """
    try:
        from core.detect.domain_tracker import get_domain_tracker  # type: ignore
    except Exception:
        get_domain_tracker = None  # type: ignore
    try:
        from metrics.streaming import CMS_DEFAULT as _CMS  # type: ignore
    except Exception:
        _CMS = None  # type: ignore
    tenant_id = resolve_tenant_id(request, tenant_id)
    items: list[dict[str, Any]] = []
    if _CMS is None or get_domain_tracker is None:
        return {'generated_at': time.time(), 'items': items, 'meta': {'note': 'sketch_unavailable'}}
    try:
        tracker = get_domain_tracker()
        # Reach into internal map for candidates (debug API)
        candidates: list[tuple[str, str]] = []  # (tenant, domain)
        tmap = getattr(tracker, '_first_seen', {})
        if isinstance(tmap, dict):
            if tenant_id and tenant_id in tmap:
                for dom in tmap.get(tenant_id, {}).keys():
                    candidates.append((tenant_id, dom))
            else:
                for ten, mp in tmap.items():
                    for dom in mp.keys():
                        candidates.append((ten, dom))
        # Estimate via CMS
        rows = []
        for ten, dom in candidates:
            key = f"{ten}::domain::{dom}"
            est = float(_CMS.estimate(key))
            if est > 0:
                rows.append({'tenant_id': ten, 'key': f'domain::{dom}', 'estimate': int(est)})
        rows.sort(key=lambda r: (-r['estimate'], r['tenant_id'], r['key']))
        items = rows[:max(1, top_n)]
    except Exception:
        items = []
    return {
        'generated_at': time.time(),
        'items': items,
        'meta': {'top_n': top_n, 'scope': tenant_id or 'all'}
    }


# --------------- shared iter helper ---------------

def _iter_decisions(limit: int = 500):
    """Yield Decision-like objects from DECISION_CACHE + alert ring."""
    count = 0
    for v in list(DECISION_CACHE.values()):
        if count >= limit:
            break
        yield v
        count += 1


# --------------- /dread_distribution ---------------

@router.get('/api/v1/analytics/dread_distribution')
async def analytics_dread_distribution(
    limit: int = Query(500, le=2000),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> dict[str, Any]:
    """DREAD composite score histogram bucketed by severity band.

    Also returns per-dimension averages so callers can see which dimension
    is dragging risk scores up or down across the observation window.
    """
    tenant_id = resolve_tenant_id(request, tenant_id)
    buckets: dict[str, int] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'unscored': 0}
    scores: list[float] = []
    dim_sums: dict[str, float] = {
        'damage': 0.0, 'reproducibility': 0.0, 'exploitability': 0.0,
        'affected': 0.0, 'discoverability': 0.0,
    }
    dim_count = 0

    for dec in _iter_decisions(limit=limit):
        if tenant_id and getattr(dec, 'tenant_id', None) not in (None, tenant_id):
            continue
        # Locate DREAD payload — stored under various attribute names across versions
        dread: Any = (
            getattr(dec, '_dread', None)
            or getattr(dec, 'dread', None)
            or getattr(dec, 'dread_scores', None)
        )
        if isinstance(dread, dict):
            score = (
                dread.get('composite')
                or dread.get('score')
                or dread.get('risk_score')
            )
            # Accumulate per-dimension if present
            for dim in dim_sums:
                val = dread.get(dim)
                if val is not None:
                    dim_sums[dim] += float(val)
            dim_count += 1
        elif isinstance(dread, (int, float)):
            score = float(dread)
            dim_count += 1
        else:
            score = None

        if score is None:
            buckets['unscored'] += 1
            continue

        s = float(score)
        scores.append(s)
        if s >= 8.0:
            buckets['critical'] += 1
        elif s >= 6.0:
            buckets['high'] += 1
        elif s >= 4.0:
            buckets['medium'] += 1
        else:
            buckets['low'] += 1

    avg = round(sum(scores) / len(scores), 3) if scores else 0.0
    dim_avgs = {
        k: round(v / dim_count, 3) if dim_count else 0.0
        for k, v in dim_sums.items()
    }
    return {
        'tenant_id': tenant_id,
        'generated_at': time.time(),
        'buckets': buckets,
        'avg_dread': avg,
        'dim_averages': dim_avgs,
        'total': len(scores) + buckets['unscored'],
        'scored': len(scores),
    }


# --------------- /top_actors ---------------

@router.get('/api/v1/analytics/top_actors')
async def analytics_top_actors(
    limit: int = Query(500, le=2000),
    top_n: int = Query(20, le=100),
    tenant_id: str | None = Header(None, alias='X-Tenant-ID'),
    request: Request = None,
) -> dict[str, Any]:
    """Top source IPs, users, and hosts by alert volume and average confidence.

    Reads from DECISION_CACHE; returns ranked lists useful for identifying
    repeat offenders and high-confidence threat actors.
    """
    tenant_id = resolve_tenant_id(request, tenant_id)

    ip_conf: dict[str, list[float]] = collections.defaultdict(list)
    user_conf: dict[str, list[float]] = collections.defaultdict(list)
    host_conf: dict[str, list[float]] = collections.defaultdict(list)

    for dec in _iter_decisions(limit=limit):
        if tenant_id and getattr(dec, 'tenant_id', None) not in (None, tenant_id):
            continue
        conf = float(getattr(dec, 'confidence', 0) or 0)

        ip = (
            getattr(dec, 'src_ip', None)
            or getattr(dec, 'ip', None)
            or getattr(dec, 'source_ip', None)
        )
        user = (
            getattr(dec, 'user', None)
            or getattr(dec, 'username', None)
            or getattr(dec, 'actor', None)
        )
        host = (
            getattr(dec, 'host', None)
            or getattr(dec, 'hostname', None)
            or getattr(dec, 'endpoint', None)
        )

        if ip:
            ip_conf[str(ip)].append(conf)
        if user:
            user_conf[str(user)].append(conf)
        if host:
            host_conf[str(host)].append(conf)

    def _rank(store: dict[str, list[float]]) -> list[dict[str, Any]]:
        rows = [
            {
                'value': k,
                'count': len(v),
                'avg_confidence': round(sum(v) / len(v), 3) if v else 0.0,
                'max_confidence': round(max(v), 3) if v else 0.0,
            }
            for k, v in store.items()
        ]
        rows.sort(key=lambda r: (-r['count'], -r['avg_confidence']))
        return rows[:max(1, top_n)]

    return {
        'tenant_id': tenant_id,
        'generated_at': time.time(),
        'top_ips': _rank(ip_conf),
        'top_users': _rank(user_conf),
        'top_hosts': _rank(host_conf),
        'meta': {'limit': limit, 'top_n': top_n},
    }


__all__ = ['router']

