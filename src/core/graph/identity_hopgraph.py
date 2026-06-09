from __future__ import annotations

import time, math
from collections import defaultdict, deque
from typing import Any, Dict, List, Tuple

from src.config import risk_loader
from src.core.graph.identity_state import IdentityStateMachine
from src.metrics import identity_metrics
from src.core import flags
from src.ml.tfidf_profile import GLOBAL_TFIDF_MANAGER
from src.ml.isolation_model import GLOBAL_ISO_MODEL
from src.ml.temporal_periodicity import GLOBAL_TEMPORAL
from src.ml.change_point import GLOBAL_CHANGE_POINT
from src.ml.seasonality import GLOBAL_SEASONALITY
from src.ml.ensemble_anomaly import GLOBAL_ENSEMBLE_ANOMALY
from src.explain.mapping import map_enrichments
from src.explain.dread_aggregator_clean import aggregate as dread_aggregate


def _is_private_ip(ip: str) -> bool:
    try:
        parts = str(ip or '').split('.')
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 127
    except Exception:
        return False


class IdentityHopGraph:
    """Lightweight identity graph for lateral pivots and escalation.

    Nodes are strings prefixed with a type: user:, session:, token:, role:, host:, cloud_resource:.
    Edges are directed and typed; we store last-seen timestamp for decay if needed.
    """

    # OAuth/token lifecycle action classifiers
    _TOKEN_ISSUE_ACTIONS = frozenset({
        'token_issue', 'authorization_code', 'access_token_issued', 'consent_granted',
        'oauth2.0', 'authorize', 'grant', 'token_grant', 'add_service_principal',
        'issue', 'app_access_token',
    })
    _TOKEN_REDEEM_ACTIONS = frozenset({
        'token_refresh', 'refresh', 'redeem', 'sign_in', 'signin', 'use_token',
        'token_use', 'token_redeemed', 'interactive_signin', 'noninteractive_signin',
    })

    def __init__(self, window_seconds: int = 24 * 3600, edge_cap: int = 100_000):
        self.window_seconds = window_seconds
        self.edge_cap = edge_cap
        # adjacency: src -> list[(dst, etype, last_ts, weight)]
        self._adj: Dict[str, List[Tuple[str, str, float, float]]] = defaultdict(list)
        self._edges_seen: deque[Tuple[float, str, str]] = deque()
        # mark interesting/high-value targets
        self._high_value: set[str] = set()
        self._state_machine = IdentityStateMachine()
        # Backwards compatibility: legacy tests referenced `_sm` directly.
        self._sm = self._state_machine
        self._recent_edges: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        # EWMA tracking: identity -> {count, ewma, mean, m2 (variance approx for normalization)}
        self._ewma: Dict[str, Dict[str, float]] = {}
        # Token lifecycle registry: token_id -> {user, asn, src_ip, ts, action}
        # Used to detect cross-ASN reuse and token user swaps (stolen token indicators)
        self._token_registry: Dict[str, Dict[str, Any]] = {}

    @property
    def adj(self) -> Dict[str, List[Tuple[str, str, float, float]]]:
        """Expose adjacency for helper utilities that duck-type HopGraph objects."""
        return self._adj

    def _prune(self) -> None:
        t0 = time.time()
        now = t0
        cutoff = now - self.window_seconds
        # prune by time from edge log and optionally shrink adjacency when cap exceeded
        while self._edges_seen and self._edges_seen[0][0] < cutoff:
            _, src, dst = self._edges_seen.popleft()
            try:
                self._adj[src] = [e for e in self._adj[src] if not (e[0] == dst and e[2] < cutoff)]
                if not self._adj[src]:
                    del self._adj[src]
            except Exception:
                pass
        # cap by count
        total = sum(len(v) for v in self._adj.values())
        if total > self.edge_cap:
            # rough prune oldest edges from edge log
            drop = total - self.edge_cap
            while drop > 0 and self._edges_seen:
                _, src, dst = self._edges_seen.popleft()
                try:
                    before = len(self._adj.get(src, []))
                    self._adj[src] = [e for e in self._adj.get(src, []) if e[0] != dst]
                    after = len(self._adj.get(src, []))
                    drop -= max(0, before - after)
                except Exception:
                    pass
        identity_metrics.observe_latency('prune', max(0.0, time.time()-t0))

    def add_edge(self, src: str, dst: str, etype: str, weight: float = 0.5) -> None:
        now = time.time()
        self._adj[src].append((dst, str(etype), now, float(weight)))
        self._edges_seen.append((now, src, dst))
        self._prune()

    def mark_high_value(self, node: str) -> None:
        self._high_value.add(node)

    # --- Ingest helpers from events ---
    def ingest_identity_event(self, ev: Dict[str, Any], aggregator: Any = None) -> None:
        t0 = time.time()
        user = (
            ev.get('user') or ev.get('user_canonical') or ev.get('username') or
            ev.get('userPrincipalName') or ev.get('user_principal_name') or
            ev.get('actor') or ev.get('account_name')
        )
        action = (ev.get('action') or ev.get('event_type') or ev.get('operation') or ev.get('event_name') or '').lower()
        src_h = ev.get('src_host') or ev.get('source_host')
        dst_h = ev.get('dest_host') or ev.get('host') or ev.get('hostname')
        role = ev.get('new_role') or ev.get('target_role')
        token = (
            ev.get('token_id') or ev.get('token') or ev.get('refresh_token_id') or
            ev.get('refreshTokenId') or ev.get('session_id')
        )
        session = ev.get('session') or ev.get('session_id')
        cloud = ev.get('cloud_resource') or ev.get('resource_arn') or ev.get('resource')

        def n_user(u: Any) -> str | None:
            return f"user:{u}" if u else None

        def n_host(h: Any) -> str | None:
            return f"host:{h}" if h else None

        if user and dst_h:
            self.add_edge(n_user(user), n_host(dst_h), 'login', weight=0.6)  # type: ignore[arg-type]
        if user and src_h and dst_h and src_h != dst_h:
            self.add_edge(n_user(user), n_host(dst_h), 'lateral_login', weight=0.8)  # type: ignore[arg-type]
        if user and role and any(k in action for k in ('su', 'runas', 'assume_role')):
            self.add_edge(n_user(user), f"role:{role}", 'priv_escalation', weight=0.9)  # type: ignore[arg-type]
            self.mark_high_value(f"role:{role}")
        if user and token:
            self.add_edge(n_user(user), f"token:{token}", 'token_issue', weight=0.4)  # type: ignore[arg-type]
        # Token lifecycle tracking — OAuth token issuance and cross-location reuse detection
        _ev_type = str(ev.get('event_type') or ev.get('action') or ev.get('operation') or '').lower()
        _asn = str(ev.get('asn') or ev.get('src_asn') or ev.get('network_asn') or '').strip()
        _src_ip = str(ev.get('src_ip') or ev.get('source_ip') or '').strip()
        _ts_ev = float(ev.get('_ts_epoch') or ev.get('timestamp_epoch') or time.time())

        if token:
            _is_issue = any(k in _ev_type for k in self._TOKEN_ISSUE_ACTIONS)
            _is_redeem = any(k in _ev_type for k in self._TOKEN_REDEEM_ACTIONS)
            _tok_key = str(token)

            if _is_issue and user:
                # Record initial token issuance context
                if _tok_key not in self._token_registry:
                    self._token_registry[_tok_key] = {
                        'user': str(user),
                        'asn': _asn or 'unknown',
                        'src_ip': _src_ip,
                        'ts': _ts_ev,
                        'action': _ev_type,
                    }
                    # Connect token node to issuance context
                    if _asn:
                        self.add_edge(f"token:{_tok_key}", f"asn:{_asn}", 'token_issued_from', weight=0.5)  # type: ignore[arg-type]

            elif _is_redeem and user and _tok_key in self._token_registry:
                _prior = self._token_registry[_tok_key]
                _prior_asn = _prior.get('asn', 'unknown')
                _prior_user = _prior.get('user', '')
                # Cross-ASN reuse: token used from different ASN than issued → stolen token indicator
                if _asn and _asn != _prior_asn and _prior_asn not in ('unknown', ''):
                    self.add_edge(
                        n_user(user), f"token:{_tok_key}", 'token_cross_asn_reuse', weight=0.95,  # type: ignore[arg-type]
                    )
                    self.mark_high_value(f"token:{_tok_key}")
                    logger.debug(
                        "IdentityHopGraph: cross-ASN token reuse — token %s issued from asn=%s, redeemed from asn=%s by user=%s",
                        _tok_key[:16], _prior_asn, _asn, user,
                    )
                # User swap: same token used by different user than who received it
                if _prior_user and str(user) != _prior_user:
                    self.add_edge(
                        n_user(user), f"token:{_tok_key}", 'token_user_swap', weight=0.98,  # type: ignore[arg-type]
                    )
                    self.mark_high_value(f"token:{_tok_key}")
                # Update registry with latest use context
                self._token_registry[_tok_key]['last_redeem_asn'] = _asn
                self._token_registry[_tok_key]['last_redeem_user'] = str(user)
                self._token_registry[_tok_key]['last_redeem_ts'] = _ts_ev

        # Token reuse / signin from unexpected foreign ASN (OAuth persistence indicator)
        if user and _asn and any(k in _ev_type for k in ('signin', 'sign_in', 'oauth', 'token', 'refresh')):
            if not _is_private_ip(_src_ip):
                _tok_edge = 'token_reuse_foreign_asn' if token else 'token_foreign_signin'
                self.add_edge(n_user(user), f"asn:{_asn}", _tok_edge, weight=0.7)  # type: ignore[arg-type]
                self.mark_high_value(f"asn:{_asn}")
        if session and user:
            self.add_edge(n_user(user), f"session:{session}", 'session', weight=0.3)  # type: ignore[arg-type]
        if user and cloud:
            self.add_edge(n_user(user), f"cloud_resource:{cloud}", 'cloud_pivot', weight=0.7)  # type: ignore[arg-type]
            self.mark_high_value(f"cloud_resource:{cloud}")
        # Basic state update (placeholder signals); refine with feature extraction module if present
        if user:
            ident = f'user:{user}'
            lateral = bool(src_h and dst_h and src_h != dst_h)
            priv_escalation_flag = bool(role and any(k in action for k in ('su', 'runas', 'assume_role')))
            cloud_flag = bool(cloud)
            # new_host heuristic: if dest host not seen before for this identity
            new_host_ratio = 1.0
            high_value_touch = False
            # Baseline update
            before_risk = self._state_machine.risk(ident)
            self._state_machine.update(ident, lateral=lateral, priv_escalation=priv_escalation_flag,
                                       cloud_pivot=cloud_flag, new_host_ratio=new_host_ratio,
                                       high_value_touch=high_value_touch)
            after_risk = self._state_machine.risk(ident)
            delta = max(0.0, after_risk - before_risk)
            # TF-IDF rarity: update per-tenant profile with resource tokens
            tokens = []
            if dst_h:
                tokens.append(str(dst_h))
            if role:
                tokens.append(str(role))
            # determine tenant (prefer explicit event tenant, else derive from user prefix)
            tenant = ev.get('tenant')
            if not tenant and isinstance(user, str) and ':' in str(user):
                tenant = str(user).split(':', 1)[0]
            prof = GLOBAL_TFIDF_MANAGER.get(tenant)
            prof.add_document(tokens)
            rarity = prof.get_rarity_score(tokens)
            # persist small updates lazily (best-effort)
            try:
                GLOBAL_TFIDF_MANAGER.save(tenant)
            except Exception:
                pass
            # Isolation forest score (feature vector: [delta, rarity])
            iso_score = GLOBAL_ISO_MODEL.score([delta, rarity])
            # Ensemble anomaly score (short window features)
            try:
                ensemble = GLOBAL_ENSEMBLE_ANOMALY.ingest(delta)
                ensemble_score = float(ensemble.get('score', 0.0))
            except Exception:
                ensemble_score = 0.0
            # Temporal periodicity
            ts = time.time()
            GLOBAL_TEMPORAL.add(ts)
            periodic_anom = GLOBAL_TEMPORAL.periodic_anomaly()
            # Seasonality residual for delta
            try:
                seasonal = GLOBAL_SEASONALITY.ingest(delta)
                seasonal_score = float(seasonal.get('resid_score', 0.0))
            except Exception:
                seasonal_score = 0.0
            # Change-point streaming (on delta)
            try:
                cp = GLOBAL_CHANGE_POINT.ingest(delta)
                cp_detected = cp is not None
            except Exception:
                cp_detected = False
            # attach ml_meta self-edge for later explainability (weight carries ensemble_score)
            try:
                self.add_edge(ident, ident, 'ml_meta', float(ensemble_score))
            except Exception:
                pass
            # Record small set of feature flags into metrics
            try:
                identity_metrics.record_event_flags({'rarity_high': rarity > 0.6, 'iso_anom': iso_score > 0.6, 'periodic': periodic_anom, 'ensemble_anom': ensemble_score > 0.6, 'seasonal_anom': seasonal_score > 0.6, 'cp_detected': cp_detected})
            except Exception:
                pass
            # EWMA residual logic (flag + config weights)
            if flags.get_flag('ENABLE_EWMA_IDENTITY', False):
                cfg = risk_loader.current_config()
                w_cfg = cfg.get('weights', {})
                ewma_cfg = cfg.get('ewma', {})
                max_boost = float(w_cfg.get('ewma_max', 0.25))
                alpha = float(ewma_cfg.get('alpha', 0.2))
                warm = int(ewma_cfg.get('warmup_min', 10))
                scale = float(ewma_cfg.get('residual_scale', 0.4))
                st = self._ewma.setdefault(ident, {'count':0.0,'ewma':0.0,'mean':0.0,'m2':0.0,'boost_last':0.0,'residual_last':0.0})
                c = st['count'] + 1.0
                # Welford update for variance of deltas
                delta_mean = delta - st['mean']
                new_mean = st['mean'] + delta_mean / c
                st['m2'] += delta_mean * (delta - new_mean)
                st['mean'] = new_mean
                st['count'] = c
                prev_ewma = st['ewma']
                st['ewma'] = prev_ewma + alpha * (delta - prev_ewma) if c > 1 else delta
                residual = delta - st['ewma']
                st['residual_last'] = residual
                boosted = False
                if c >= warm:
                    var = (st['m2'] / (c-1)) if c > 2 else 0.0
                    std = math.sqrt(max(1e-9, var))
                    norm = residual / std if std > 0 else 0.0
                    norm_clamped = max(-5.0, min(5.0, norm))
                    boost = max(0.0, norm_clamped * scale)
                    if boost > 0:
                        boost = min(boost, max_boost)
                        # Apply boost by directly increasing internal risk store
                        # (simple approach: call state machine update with a synthetic increment)
                        self._state_machine._risk[ident] = min(5.0, self._state_machine._risk.get(ident,0.0) + boost)  # type: ignore
                        st['boost_last'] = boost
                        boosted = True
                    identity_metrics.observe_ewma(residual, norm, boosted)
                else:
                    identity_metrics.observe_ewma(residual, 0.0, False)
                # Mutual exclusion: if periodic anomaly is strong, do not double-boost with EWMA
                if periodic_anom and boosted:
                    # revert boost (conservative) and report
                    prev = self._state_machine._risk.get(ident,0.0)
                    self._state_machine._risk[ident] = max(0.0, prev - st.get('boost_last',0.0))  # type: ignore
                    st['boost_last'] = 0.0
                    boosted = False
                    # record that periodic took precedence
                    identity_metrics.record_event_flags({'ewma_preempted_by_periodic': True})
            self._recent_edges[ident].append({
                'ts': time.time(),
                'src_host': src_h,
                'dst_host': dst_h,
                'action': action,
                'role': role,
                'cloud': cloud,
            })
            # Emit ML signals to optional per-assessment aggregator so
            # assessment_worker Stage 5g+ can read them back for cluster elevation.
            if aggregator is not None:
                try:
                    _ewma_res = 0.0
                    if ident in self._ewma:
                        _ewma_res = float(self._ewma[ident].get('residual_last', 0.0))
                    _is_anom = (iso_score > 0.6 or ensemble_score > 0.6)
                    aggregator.record(
                        user=str(user),
                        iso_score=iso_score,
                        ensemble_score=ensemble_score,
                        rarity=rarity,
                        ewma_residual=_ewma_res,
                        is_anomaly=_is_anom,
                    )
                except Exception:
                    pass
        identity_metrics.observe_latency('update', max(0.0, time.time()-t0))

    def identity_snapshot(self, identity: str) -> Dict[str, Any]:
        snap = self._state_machine.snapshot(identity)
        cfg_hash = risk_loader.config_hash()
        snap['config_version'] = cfg_hash
        try:
            identity_metrics.set_config_version(cfg_hash)
        except Exception:
            pass
        snap['recent'] = list(self._recent_edges.get(identity, []))
        if identity in self._ewma:
            st = self._ewma[identity]
            snap['ewma'] = {
                'count': int(st.get('count',0)),
                'ewma': round(st.get('ewma',0.0),6),
                'residual_last': round(st.get('residual_last',0.0),6),
                'boost_last': round(st.get('boost_last',0.0),6),
            }
        elif flags.get_flag('ENABLE_EWMA_IDENTITY', False):
            # Provide empty scaffold for transparency even if not warmed up
            snap['ewma'] = {
                'count': 0,
                'ewma': 0.0,
                'residual_last': 0.0,
                'boost_last': 0.0,
            }
        return snap

    # --- Persistence helpers (SQLite snapshot with metadata) ---
    def save_snapshot(self, path: str) -> bool:
        """Save a snapshot of adjacency, ewma, and high_value set into an SQLite DB.

        Schema (simple):
          - edges(src TEXT, dst TEXT, etype TEXT, ts REAL, weight REAL)
          - meta(k TEXT PRIMARY KEY, v TEXT)

        This is atomic (single DB file) and stores ewma/high_value in meta as JSON.
        """
        try:
            import sqlite3, json
            from pathlib import Path

            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(p), timeout=10)
            cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS edges(src TEXT, dst TEXT, etype TEXT, ts REAL, weight REAL)")
            cur.execute("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT)")
            cur.execute("DELETE FROM edges")
            cur.execute("DELETE FROM meta")
            # bulk insert edges
            to_insert = []
            for src, lst in self._adj.items():
                for (dst, etype, ts, w) in lst:
                    to_insert.append((src, dst, etype, float(ts), float(w)))
            if to_insert:
                cur.executemany("INSERT INTO edges(src,dst,etype,ts,weight) VALUES(?,?,?,?,?)", to_insert)
            # store ewma and high_value as JSON
            cur.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", ('ewma', json.dumps(self._ewma)))
            cur.execute("INSERT OR REPLACE INTO meta(k,v) VALUES(?,?)", ('high_value', json.dumps(list(self._high_value))))
            conn.commit()
            conn.close()
            return True
        except Exception:
            return False

    def load_snapshot(self, path: str) -> bool:
        """Load a snapshot produced by save_snapshot. This will replace in-memory structures."""
        try:
            import sqlite3, json
            from pathlib import Path

            p = Path(path)
            if not p.exists():
                return False
            conn = sqlite3.connect(str(p), timeout=10)
            cur = conn.cursor()
            cur.execute("SELECT src,dst,etype,ts,weight FROM edges")
            rows = cur.fetchall()
            self._adj = defaultdict(list)
            for (src, dst, etype, ts, w) in rows:
                try:
                    self._adj[src].append((dst, etype, float(ts), float(w)))
                except Exception:
                    pass
            cur.execute("SELECT k,v FROM meta")
            for k, v in cur.fetchall():
                if k == 'ewma':
                    try:
                        self._ewma = json.loads(v)
                    except Exception:
                        self._ewma = {}
                if k == 'high_value':
                    try:
                        self._high_value = set(json.loads(v))
                    except Exception:
                        self._high_value = set()
            conn.close()
            return True
        except Exception:
            return False

    # --- Queries ---
    def find_top_paths(self, start: str, limit: int = 5, depth: int = 5) -> List[Dict[str, Any]]:
        """Bounded BFS for simple paths and a coarse risk score per path."""
        results: List[Dict[str, Any]] = []
        start = str(start)
        frontier: List[Tuple[List[str], float]] = [([start], 0.0)]
        seen_paths: set[Tuple[str, ...]] = set()
        while frontier and len(results) < max(1, limit):
            path, score = frontier.pop(0)
            cur = path[-1]
            if len(path) > depth:
                continue
            # consider terminal if hitting a high-value node (role/cloud_resource)
            if cur in self._high_value or cur.startswith(('role:', 'cloud_resource:')):
                key = tuple(path)
                if key not in seen_paths:
                    results.append({'path': list(path), 'risk': float(self._score_path(path))})
                    seen_paths.add(key)
            from src.core.rules.join_helpers import _get_adj_list  # type: ignore
            adj = _get_adj_list(self._adj if callable(getattr(self,'_adj', None)) else self)
            for (dst, etype, _ts, w) in list(adj(cur))[:25]:
                if dst in path:
                    continue
                step_boost = self._edge_risk_boost(cur, dst, etype, w)
                frontier.append((path + [dst], score + step_boost))
        results.sort(key=lambda x: x['risk'], reverse=True)
        return results[:limit]

    def _edge_risk_boost(self, src: str, dst: str, etype: str, w: float) -> float:
        etype = etype.lower()
        boost = 0.0
        if etype in {'priv_escalation'}:
            boost += 0.6
        if etype in {'lateral_login', 'cloud_pivot'}:
            boost += 0.4
        if dst.startswith('role:'):
            boost += 0.3
        if dst.startswith('cloud_resource:'):
            boost += 0.3
        return boost + (w * 0.2)

    def _score_path(self, path: List[str]) -> float:
        score = 0.0
        for i in range(max(0, len(path) - 1)):
            src = path[i]
            dst = path[i + 1]
            from src.core.rules.join_helpers import _get_adj_list  # type: ignore
            adj = _get_adj_list(self._adj if callable(getattr(self,'_adj', None)) else self)
            # find first matching edge record for weight and type
            edge = next(((d, t, ts, w) for (d, t, ts, w) in adj(src) if d == dst), None)
            if edge:
                score += self._edge_risk_boost(src, edge[0], edge[1], edge[3])
        # slight length dampening
        return max(0.0, score - max(0, len(path) - 2) * 0.05)

    # --- Explainability tags ---
    def explain_path(self, path: List[str]) -> Dict[str, Any]:
        mitre: List[str] = []
        stride: List[str] = []
        pasta_stage = 'TA5'  # Attack Modeling (coarse)
        dread = {'damage': 0.0, 'repro': 0.5, 'exploit': 0.7, 'affected': 0.5, 'discover': 0.6}
        mapping_details: List[Dict[str, Any]] = []
        ml_scores: Dict[str, float] = {}
        # Attempt to collect CVE evidence from nodes' recent metadata (best-effort)
        collected_cves: list[dict] = []
        for i in range(max(0, len(path) - 1)):
            src = path[i]
            dst = path[i + 1]
            from src.core.rules.join_helpers import _get_adj_list  # type: ignore
            adj = _get_adj_list(self._adj if callable(getattr(self,'_adj', None)) else self)
            etype = next((t for (d, t, _ts, _w) in adj(src) if d == dst), '')
            et = etype.lower()
            if et == 'lateral_login':
                mitre += ['T1021', 'T1078']
                stride += ['Elevation of Privilege']
                mapping_details.append({'edge': 'lateral_login', 'src': src, 'dst': dst})
            if et == 'priv_escalation':
                mitre += ['T1548']
                stride += ['Elevation of Privilege']
                dread['damage'] = max(dread['damage'], 0.7)
                mapping_details.append({'edge': 'priv_escalation', 'src': src, 'dst': dst})
            if et == 'cloud_pivot':
                mitre += ['T1550']
                stride += ['Spoofing']
                dread['affected'] = max(dread['affected'], 0.7)
                mapping_details.append({'edge': 'cloud_pivot', 'src': src, 'dst': dst})
            # collect any cve_summary present on node metadata (if stored in recent edges)
            try:
                recent = self._recent_edges.get(dst, [])
                for r in list(recent)[-3:]:
                    cs = r.get('cve_summary') or r.get('sbom_cves') or None
                    if cs and isinstance(cs, list):
                        for c in cs:
                            if isinstance(c, dict) and c.get('cve'):
                                collected_cves.append(c)
            except Exception:
                pass
        # include cve evidence and aggregate DREAD with cve list and potential anomaly scores
        try:
            # compute combined anomaly (mean of ml_meta self-edges if present)
            if ml_scores:
                anomaly = float(sum(ml_scores.values()) / max(1, len(ml_scores)))
            else:
                anomaly = 0.0
            drought_inputs = {'cves': collected_cves, 'anomaly': anomaly, 'path_length': len(path)}
            dread_calc = dread_aggregate(drought_inputs)
            dread = {**dread, **dread_calc}
        except Exception:
            dread_calc = {}

        return {
            'mitre': sorted(set(mitre)),
            'stride': sorted(set(stride)),
            'pasta': pasta_stage,
            'dread': dread,
            'mapping_details': mapping_details,
            'ml_scores': ml_scores,
            'cve_evidence': collected_cves,
        }


# Global instance for simple API usage
GLOBAL_IDENTITY_GRAPH = IdentityHopGraph()

# Attempt to load persisted snapshot if configured and start autosave loop
try:  # Best-effort, do not fail runtime if persistence unavailable
    from src.core.graph.persistence_sqlite import maybe_load, GLOBAL_HOPGRAPH_PERSIST  # type: ignore
    maybe_load(GLOBAL_IDENTITY_GRAPH)
    GLOBAL_HOPGRAPH_PERSIST.start_autosave(GLOBAL_IDENTITY_GRAPH)
except Exception:
    pass

# Compatibility wrappers: provide a consistent public API across graphs
def ingest_flow(ev: dict) -> None:
    """Adapter: accept an event-like dict and forward to identity ingest."""
    return GLOBAL_IDENTITY_GRAPH.ingest_identity_event(ev)

def find_paths(start: str, limit: int = 5, depth: int = 5):
    return GLOBAL_IDENTITY_GRAPH.find_top_paths(start, limit=limit, depth=depth)

def explain(path: list):
    return GLOBAL_IDENTITY_GRAPH.explain_path(path)
