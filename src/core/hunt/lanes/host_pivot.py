"""Host Pivot Lane

Flags potential lateral movement pivots using simple state and hopgraph context.

Signals:
 - First-time peer connection between internal hosts
 - Rapid fan-out: user touches multiple hosts in a short window
 - Off-hours new peer

Emits advisory factors; prefixed by lane_host_pivot:* by the registry.
"""
from __future__ import annotations

import time
from typing import Deque, Dict, List, Set, Tuple
from collections import deque

try:
    from core.graph.hopgraph_lite import get_graph
except Exception:  # pragma: no cover
    def get_graph():  # type: ignore
        return None


try:
    from core.detect.cusum import CUSUM
except Exception:
    CUSUM = None  # type: ignore

try:
    from core.detect.isolation_forest import IsolationForestDetector
except Exception:
    IsolationForestDetector = None  # type: ignore


class HostPivotLane:
    name = 'host_pivot'

    def __init__(self):
        # Rolling per-user peer set (in-process memory)
        self._user_peers: Dict[str, Set[str]] = {}
        self._user_last_ts: Dict[str, float] = {}
        # Temporal detectors per user
        self._cusum: Dict[Tuple[str, str], CUSUM] = {}  # (user, feature)->CUSUM
        self._if_models: Dict[Tuple[str, str], IsolationForestDetector] = {}  # (role,user)->model
        self._if_history: Dict[str, Deque[List[float]]] = {}  # user->deque of feature vectors
        self._port_hist: Dict[str, Deque[int]] = {}
        # Darktrace-equivalent: per-device connection profile (ASN + country baseline)
        # device_id → set of (asn, country) tuples seen historically
        self._device_asn_profile: Dict[str, Set[Tuple[str, str]]] = {}
        self._device_profile_ts: Dict[str, Deque[float]] = {}  # last seen timestamps

    async def run(self, envelope, context):
        e = envelope.event
        user = (e.get('user') or '').lower()
        src = (e.get('src_host') or e.get('host') or '').lower()
        dst = (e.get('dest_host') or e.get('dst_host') or '').lower()
        off_hours = bool(e.get('context_off_hours'))
        role = (e.get('role') or 'user').lower()
        now = time.time()

        factors: list[str] = []
        if user and dst:
            peers = self._user_peers.setdefault(user, set())
            pre_count = len(peers)
            first_time_peer = dst not in peers
            if first_time_peer:
                factors.append('first_time_peer_contact')
                if off_hours:
                    factors.append('first_time_peer_off_hours')
            peers.add(dst)
            # Rapid fan-out heuristic within a short window
            last = self._user_last_ts.get(user, 0.0)
            if (now - last) < 120 and len(peers) >= 3:  # 3 peers within 2 minutes
                factors.append('rapid_peer_fanout')
            self._user_last_ts[user] = now

            # Temporal features
            peer_count = float(len(peers))
            peer_delta = float(len(peers) - pre_count)
            dt = float(max(0.0, now - last)) if 'last' in locals() else 9999.0
            off = 1.0 if off_hours else 0.0
            # Failed->success auth ratio (best-effort)
            fail = float(e.get('auth_failed') or 0.0)
            succ = float(e.get('auth_success') or e.get('auth_succeeded') or 0.0)
            ratio = (fail / max(1.0, succ)) if (fail or succ) else 0.0
            # Port entropy over recent window (if dst_port provided)
            port = e.get('dst_port') or e.get('dest_port')
            if isinstance(port, int):
                ph = self._port_hist.setdefault(user, deque(maxlen=32))
                ph.append(int(port))
            ph = self._port_hist.get(user, deque())
            import math
            if ph:
                counts = {}
                for p in ph:
                    counts[p] = counts.get(p, 0) + 1
                total = float(len(ph))
                ent = 0.0
                for c in counts.values():
                    pr = c / total
                    ent -= pr * math.log2(pr)
                # normalize by max bits for bucket count
                max_bits = math.log2(max(1, len(counts))) if counts else 1.0
                port_entropy = ent / max(1e-6, max_bits)
            else:
                port_entropy = 0.0

            # CUSUM on peer_count (detect abrupt change)
            try:
                if CUSUM is not None:
                    key = (user, 'peer_count')
                    model = self._cusum.get(key)
                    if model is None:
                        model = CUSUM(target_mean=1.0, k=0.5, h=3.0)
                        self._cusum[key] = model
                    if model.update(peer_count):
                        factors.append('temporal_shift_user_peering')
            except Exception:
                pass

            # Isolation Forest on minimal vector [peer_count, off_hours, min(dt, 600)/600]
            try:
                if IsolationForestDetector is not None:
                    hist = self._if_history.setdefault(user, deque(maxlen=64))
                    vec = [peer_count, off, min(dt, 600.0) / 600.0, peer_delta, ratio, float(port_entropy)]
                    hist.append(vec)
                    if len(hist) >= 20:
                        mkey = (role or 'user', user)
                        model = self._if_models.get(mkey)
                        if model is None:
                            model = IsolationForestDetector(n_estimators=50, max_samples='auto', random_state=42)
                            self._if_models[mkey] = model
                        # Fit occasionally (every 10th sample) to keep cheap
                        if len(hist) % 10 == 0:
                            try:
                                model.fit(list(hist))
                            except Exception:
                                pass
                        score = model.score(vec)
                        if score >= 0.85:  # conservative
                            factors.append('if_lateral_anomaly')
            except Exception:
                pass

        # ── Darktrace-equivalent: device connection profile deviation ────────
        # Maintain a per-device baseline of (ASN, country) pairs seen historically.
        # Any connection to an ASN/country not in the device's profile is flagged.
        # No rules required — purely profile-based, like Darktrace's "Self-Learning AI".
        try:
            device_id = src or user or ''
            asn = str(ev.get('src_asn') or ev.get('asn') or '').strip()
            country = str(ev.get('src_country') or ev.get('country') or '').strip().upper()
            dst_asn = str(ev.get('dst_asn') or ev.get('dest_asn') or '').strip()
            dst_country = str(ev.get('dst_country') or ev.get('dest_country') or '').strip().upper()

            if device_id and (asn or country or dst_asn or dst_country):
                profile = self._device_asn_profile.setdefault(device_id, set())
                ts_ring = self._device_profile_ts.setdefault(device_id, deque(maxlen=500))

                # Check destination connection profile
                for a, c in ((dst_asn, dst_country), (asn, country)):
                    if not (a or c):
                        continue
                    pair = (a, c)
                    if len(ts_ring) >= 5:  # require at least 5 events before flagging
                        if pair not in profile:
                            factors.append('darktrace:device_new_asn_country_connection')
                            # Escalate for high-risk countries (*.sg, CN, RU, KP, IR)
                            if c in ('CN', 'RU', 'KP', 'IR', 'SG'):
                                factors.append(f'darktrace:device_new_high_risk_country_{c}')
                    profile.add(pair)
                    ts_ring.append(now)
        except Exception:
            pass

        # Consult hopgraph for broader context factors (best-effort)
        try:
            g = get_graph()
            if g is not None:
                # Provide the event as an observation for typed edge updates
                g.observe({'user': user, 'host': src or None, 'peer': dst or None, 'edge_type': 'net'})
                # If hopgraph path templates flagged a hit recently, add a corroboration
                if g.path_hit_recent(60):  # any path hit in last minute
                    factors.append('graph_path_template_match')
                # Optional bounded walk on triggers to gauge neighborhood density
                try:
                    from core.feature_flags import is_enabled
                except Exception:
                    def is_enabled(_): return False
                if (first_time_peer or 'if_lateral_anomaly' in factors) and is_enabled('hopgraph_walk') and user:
                    walk = g.bounded_walk(('user', user), max_depth=2, branch_cap=20)
                    if isinstance(walk, list) and len(walk) >= 15:
                        factors.append('graph_walk_dense_neighborhood')
        except Exception:
            pass

        if factors:
            envelope.add_emission(self.name, factors, notes=None, latency_ms=0.0)


def build():
    return HostPivotLane()
