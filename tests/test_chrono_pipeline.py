"""ChronoGraph pipeline (extracted Stage 5i/5j) — accumulate + elevate_clusters.

Directly unit-tests the long-horizon detection the worker and the gate both run:
the cumulative <350MB-per-transfer exfil to one destination becomes a factor on the
actor's breach cluster, even though no single transfer is anomalous.
"""
from __future__ import annotations

from src.core.chrono.sketch_store import ChronoSketchStore
from src.core.chrono.pipeline import accumulate, elevate_clusters

_REF = 1_744_000_000.0  # data-time anchor (April 2026), far from wall-clock now


def _exfil_rows(user="martin.chen", dest="martin-chen.sharepoint.com", n=30, mb=200):
    # n transfers of `mb` MB each: every transfer benign (<350MB), cumulative ~6GB.
    rows = []
    for i in range(n):
        rows.append({
            "user_canonical": user, "hostname": "ws-martin-01",
            "dst_host": dest, "bytes_sent": str(mb * 1_000_000),
            "_source_type": "network", "_ts_epoch": _REF - (n - i) * 3600,
        })
    return rows


def test_cumulative_exfil_attaches_to_actor_cluster():
    chrono = ChronoSketchStore()
    rows = _exfil_rows()
    accum = accumulate(rows, chrono)
    # ref_ts is the MAX event time (data-time anchor), not wall-clock now.
    assert 0 < accum.ref_ts <= _REF
    cluster = {"verdict": "VALIDATED_BREACH", "shared_users": ["martin.chen"]}
    elevate_clusters([cluster], accum, chrono)
    # The per-destination cumulative bytes (>2GB floor) surfaced as a factor + recorded.
    assert "exfil:cumulative_bytes_anomaly" in (cluster.get("factor_tags") or [])
    dests = cluster.get("_exfil_destinations") or {}
    assert any("martin-chen.sharepoint.com" in str(r.get("destination", "")).lower()
               for r in dests.values())


def test_below_floor_exfil_not_flagged():
    # A small total (well under the 2GB floor, no lookalike) must NOT flag.
    chrono = ChronoSketchStore()
    rows = _exfil_rows(n=3, mb=50)   # ~150MB total
    accum = accumulate(rows, chrono)
    cluster = {"verdict": "VALIDATED_BREACH", "shared_users": ["martin.chen"]}
    elevate_clusters([cluster], accum, chrono)
    assert "martin-chen.sharepoint.com" not in str(cluster.get("_exfil_destinations") or {})


def test_non_breach_cluster_not_elevated():
    chrono = ChronoSketchStore()
    accum = accumulate(_exfil_rows(), chrono)
    cluster = {"verdict": "SUSPECTED_BREACH", "shared_users": ["martin.chen"]}
    elevate_clusters([cluster], accum, chrono)
    assert not cluster.get("_chrono_factors")
