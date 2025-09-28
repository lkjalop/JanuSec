"""Hunt Sidecar Session Manager

Manages lifecycle of a hunt session: INIT -> RUNNING -> COMPLETE/ABORT.
Integrates with cost estimator & (future) HopGraph ingestion pipeline.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional, List, Tuple
from collections import Counter
import time
import threading
from core.finops.cost_estimator import estimate_hunt_cost  # type: ignore
from core.finops.finops_manager import get_finops_manager
from .hopgraph_light import get_hopgraph
from .fusion_heuristics import aggregate as aggregate_features
from .model_orchestrator import select_model
try:
    from prometheus_client import Counter as _PromCounter, Histogram as _PromHistogram  # type: ignore
except Exception:  # pragma: no cover
    _PromCounter = None  # type: ignore

_tier_counter = None
_replay_latency_hist = None
_cost_guard_counter = None
_artifact_fail_counter = None
if _PromCounter and '_hunt_model_tier_selection_total' not in globals():
    try:
        _tier_counter = _PromCounter('hunt_model_tier_selection_total', 'Model tier selections during hunts', ['tier','reason'])
        _cost_guard_counter = _PromCounter('cost_guard_triggers_total','Adaptive cost guard trigger count',['tenant'])
        _artifact_fail_counter = _PromCounter('artifact_write_failures_total','Artifact write failures',['reason'])
        if _PromHistogram:
            _replay_latency_hist = _PromHistogram('hunt_replay_latency_seconds','Replay execution latency (s)')
    except Exception:
        _tier_counter = None
from core.reporting.hunt_report import to_json, to_markdown
from .provenance import compute_session_hash
import os, json
try:
    from prometheus_client import Gauge as _PromGauge, Counter as _PromCounter2  # type: ignore
except Exception:
    _PromGauge = None
    _PromCounter2 = None

@dataclass
class HuntSession:
    id: str
    tenant: str
    window_hours: int
    model_enabled: bool
    estimate_units: float
    estimate_margin: float
    start_time: float = 0.0
    end_time: float = 0.0
    status: str = 'INIT'
    report: Dict[str, object] = field(default_factory=dict)
    model_tiers_used: Dict[int,int] = field(default_factory=dict)
    factors: Dict[str,float] = field(default_factory=dict)
    tier_timeline: List[Dict[str, object]] = field(default_factory=list)
    artifact_ref: Optional[str] = None
    replay_hash: Optional[str] = None
    baseline_snapshot: dict | None = None
    coverage_delta: dict | None = None
    factor_emergence: List[Dict[str, object]] = field(default_factory=list)
    embedding_simulation: Dict[str, object] | None = None

class SidecarSessionManager:
    def __init__(self):
        self._sessions: Dict[str,HuntSession] = {}
        self._lock = threading.Lock()
        self._background_threads: Dict[str, threading.Thread] = {}
        self._coverage_history: List[dict] = []  # ring buffer of recent coverage deltas
        # Per-tenant coverage deltas (mirrors global ring buffer)
        self._coverage_history_by_tenant: Dict[str, List[dict]] = {}
        import os
        # Retention sizing: prefer explicit COVERAGE_HISTORY_RETENTION else fallback to COVERAGE_HISTORY_MAX
        try:
            self._coverage_history_max = int(os.getenv('COVERAGE_HISTORY_RETENTION') or os.getenv('COVERAGE_HISTORY_MAX','200'))
        except Exception:
            self._coverage_history_max = 200
        # Rolling emergence memory per factor for promotion workflow
        self._emergence_history: Dict[str, List[float]] = {}  # factor -> list of last emergence scores
        self._emergence_history_max = int(os.getenv('EMERGENCE_HISTORY_MAX','30'))
        # Sustained promotion threshold defaults (can be tuned via env)
        self._promotion_min_sessions = int(os.getenv('PROMOTION_MIN_SESSIONS','3'))
        self._promotion_min_avg = float(os.getenv('PROMOTION_MIN_AVG_SCORE','0.15'))
        self._promotion_min_median = float(os.getenv('PROMOTION_MIN_MEDIAN_SCORE','0.10'))
        # Quotas
        self._max_hunts_window = int(os.getenv('MAX_HUNTS_PER_TENANT_WINDOW','0') or 0) or None
        self._hunts_window_seconds = int(os.getenv('HUNTS_PER_TENANT_WINDOW_SECONDS','3600'))
        self._tenant_hunt_starts: Dict[str, List[float]] = {}

    def preview(self, tenant: str, window_hours: int, model_enabled: bool) -> Dict[str, object]:
        est = estimate_hunt_cost(window_hours, tenant, model_enabled)
        return est

    def start(self, session_id: str, tenant: str, window_hours: int, model_enabled: bool, budget_cap_units: float | None = None, async_run: bool = False) -> HuntSession:
        # Quota enforcement (hunts per tenant window)
        if self._max_hunts_window:
            now = time.time()
            starts = self._tenant_hunt_starts.setdefault(tenant, [])
            cutoff = now - self._hunts_window_seconds
            # prune
            starts[:] = [t for t in starts if t >= cutoff]
            if len(starts) >= self._max_hunts_window:
                raise ValueError('tenant_hunt_quota_exceeded')
            starts.append(now)
        est = estimate_hunt_cost(window_hours, tenant, model_enabled)
        if budget_cap_units is not None and est['cost_units_estimate'] > budget_cap_units:
            raise ValueError('estimate_exceeds_budget_cap')
        sess = HuntSession(id=session_id, tenant=tenant, window_hours=window_hours, model_enabled=model_enabled,
                           estimate_units=est['cost_units_estimate'], estimate_margin=est['error_margin_units'])
        sess.start_time = time.time(); sess.status='RUNNING'
        # Capture baseline snapshot prior to hunt analysis for coverage delta
        sess.baseline_snapshot = self._capture_baseline_snapshot(max_events=500)
        with self._lock:
            self._sessions[session_id] = sess
        if async_run:
            t = threading.Thread(target=self._execute, args=(sess,), daemon=True)
            self._background_threads[session_id] = t
            t.start()
        else:
            self._execute(sess)
        return sess

    def _execute(self, sess: HuntSession):
        # Placeholder severity & confidence seeds
        severity = 0.5 if sess.window_hours <= 24 else 0.75
        confidence = 0.35  # low to trigger possible escalation
        fm = get_finops_manager()
        # Budget remaining approximation (no tenant budgets yet) assume 1.0
        availability = {0: True, 1: True, 2: True, 3: True, 4: False}
        decision = select_model(severity, confidence, 1.0, availability)
        sess.model_tiers_used[decision.tier] = sess.model_tiers_used.get(decision.tier,0)+1
        sess.tier_timeline.append({'ts': time.time(), 'tier': decision.tier, 'reason': decision.reason})
        if _tier_counter:
            try:
                _tier_counter.labels(tier=str(decision.tier), reason=decision.reason).inc()
            except Exception:
                pass
        # Simulate graph population
        hg = get_hopgraph()
        hg.add_node(f'user:alice', 'user')
        hg.add_node('host:web01','asset')
        hg.add_edge('user:alice','host:web01','login')
        factors = aggregate_features(hg)
        # Adaptive cost guard (simulation): if projected overrun > 20%, halt model escalation
        projected_units = sess.estimate_units * 1.22  # naive projection
        if projected_units > (sess.estimate_units + sess.estimate_margin):
            sess.factors['cost_guard_triggered'] = 1.0
            if _cost_guard_counter:
                try: _cost_guard_counter.labels(tenant=sess.tenant).inc()
                except Exception: pass
        sess.factors = factors
        # Assemble report
        sess.end_time = time.time(); sess.status='COMPLETE'
        duration = sess.end_time - sess.start_time
        actual_units = round(sess.estimate_units * 1.05,2)  # placeholder 5% over
        cost_delta_pct = (actual_units - sess.estimate_units)/max(1e-6,sess.estimate_units)
        # Artifact & replay provenance placeholders
        sess.replay_hash = compute_session_hash(sess.window_hours, sess.model_enabled, sess.tenant, sess.estimate_units)
        sess.artifact_ref = f"artifact:{sess.id}:{sess.replay_hash[:10]}"
        base_report = {
            'session_id': sess.id,
            'tenant': sess.tenant,
            'window_hours': sess.window_hours,
            'duration_seconds': round(duration,2),
            'estimate_units': sess.estimate_units,
            'actual_units': actual_units,
            'delta_pct': round(cost_delta_pct*100,2),
            'factors': factors,
            'model_tiers_used': sess.model_tiers_used,
            'status': sess.status
        }
        # Attach structured & markdown forms
        sess.report = base_report
        sess.report_json = to_json(base_report)
        sess.report_markdown = to_markdown(base_report)
        # Compute coverage delta (baseline vs hunt approximation)
        try:
            sess.coverage_delta = self._compute_coverage_delta(sess)
        except Exception:
            sess.coverage_delta = None
        # Append coverage delta to history
        if sess.coverage_delta:
            cd = dict(sess.coverage_delta)
            cd['timestamp'] = time.time()
            with self._lock:
                # Global ring
                self._coverage_history.append(cd)
                if len(self._coverage_history) > self._coverage_history_max:
                    self._coverage_history = self._coverage_history[-self._coverage_history_max:]
                # Tenant ring
                t_list = self._coverage_history_by_tenant.setdefault(sess.tenant, [])
                t_list.append(cd)
                if len(t_list) > self._coverage_history_max:
                    self._coverage_history_by_tenant[sess.tenant] = t_list[-self._coverage_history_max:]
                # Gauge update
                if _PromGauge and not hasattr(self.__class__, '_coverage_hist_gauge'):
                    try:
                        self.__class__._coverage_hist_gauge = _PromGauge('coverage_history_entries','Coverage history ring size')
                    except Exception:
                        self.__class__._coverage_hist_gauge = None
                if hasattr(self.__class__,'_coverage_hist_gauge') and getattr(self.__class__,'_coverage_hist_gauge'):
                    try: self.__class__._coverage_hist_gauge.set(len(self._coverage_history))
                    except Exception: pass
        # Factor emergence scoring
        try:
            sess.factor_emergence = self._compute_factor_emergence(sess)
            if sess.factor_emergence:
                # Attach top N summary to report
                base_report['factor_emergence_top'] = sess.factor_emergence[:10]
                # Update rolling emergence history for promotion workflow
                for row in sess.factor_emergence:
                    if row.get('meta'):
                        continue
                    f = row.get('factor'); score = row.get('emergence_score')
                    if f is None or score is None:
                        continue
                    hist = self._emergence_history.setdefault(f, [])
                    hist.append(float(score))
                    if len(hist) > self._emergence_history_max:
                        self._emergence_history[f] = hist[-self._emergence_history_max:]
        except Exception:
            sess.factor_emergence = []
        # Selective embedding simulation
        try:
            sess.embedding_simulation = self._simulate_selective_embedding(sess)
            if sess.embedding_simulation:
                base_report['embedding_simulation'] = sess.embedding_simulation
        except Exception:
            sess.embedding_simulation = None
        # Persist artifact archive
        try:
            os.makedirs('artifacts/hunts', exist_ok=True)
            archive = {
                'session': base_report,
                'timeline': sess.tier_timeline,
                'replay_hash': sess.replay_hash,
                'factors': sess.factors
            }
            with open(f'artifacts/hunts/{sess.id}.json','w',encoding='utf-8') as f:
                json.dump(archive, f, indent=2)
        except Exception as e:
            if _artifact_fail_counter:
                try: _artifact_fail_counter.labels(reason=type(e).__name__).inc()
                except Exception: pass

    def get(self, session_id: str) -> HuntSession | None:
        return self._sessions.get(session_id)

    def report(self, session_id: str) -> Dict[str, object] | None:
        sess = self.get(session_id)
        if not sess:
            return None
        return {
            'report': sess.report,
            'report_json': getattr(sess, 'report_json', None),
            'report_markdown': getattr(sess, 'report_markdown', None)
        }

    def timeline(self, session_id: str) -> List[Dict[str, object]]:
        sess = self.get(session_id)
        return [] if not sess else sess.tier_timeline

    def graph_snapshot(self, session_id: str, fmt: str = 'json') -> Dict[str, object] | str:
        # Minimal snapshot for now (since we add only a few nodes)
        from .hopgraph_light import get_hopgraph
        hg = get_hopgraph()
        sg = hg.subgraph(['user:alice'])
        if fmt == 'dot':
            lines = ['digraph G {']
            for n in sg['nodes']:
                lines.append(f'  "{n["id"]}" [label="{n["id"]}:{n.get("kind")}"];')
            for e in sg['edges']:
                lines.append(f'  "{e["src"]}" -> "{e["dst"]}" [label="{e.get("kind")}"];')
            lines.append('}')
            return '\n'.join(lines)
        return sg

    def replay(self, original_session_id: str, new_session_id: str | None = None, async_run: bool = False) -> HuntSession:
        orig = self.get(original_session_id)
        if not orig:
            raise ValueError('original_not_found')
        new_id = new_session_id or f"replay_of_{original_session_id}_{int(time.time())}"
        # Use same window & model flags; ignore budget cap for replay
        start_ts = time.time()
        sess = self.start(new_id, orig.tenant, orig.window_hours, orig.model_enabled, budget_cap_units=None, async_run=async_run)
        if not async_run and _replay_latency_hist:
            try: _replay_latency_hist.observe(time.time()-start_ts)
            except Exception: pass
        # Tag report with replay_of
        sess.report['replay_of'] = original_session_id
        return sess

    def coverage_trends(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(self._coverage_history[-limit:])

    def coverage_trends_tenant(self, tenant: str, limit: int = 50) -> List[dict]:
        with self._lock:
            t_list = self._coverage_history_by_tenant.get(tenant, [])
            return list(t_list[-limit:])

    def promotion_candidates(self, min_sessions: int = 2, top_n: int = 15) -> List[dict]:
        # Aggregate factor emergence entries (exclude meta rows)
        factor_stats: Dict[str, Dict[str, float]] = {}
        tenant_factor_sessions: Dict[str, Dict[str,int]] = {}
        with self._lock:
            sessions = list(self._sessions.values())
        for s in sessions:
            for row in getattr(s, 'factor_emergence', []) or []:
                if row.get('meta'):  # skip meta
                    continue
                f = row.get('factor')
                if not f:
                    continue
                st = factor_stats.setdefault(f, {'sessions':0,'emergence_sum':0.0,'max_score':0.0})
                st['sessions'] += 1
                score = float(row.get('emergence_score',0.0))
                st['emergence_sum'] += score
                if score > st['max_score']:
                    st['max_score'] = score
                # tenant breakdown
                tf = tenant_factor_sessions.setdefault(s.tenant, {})
                tf[f] = tf.get(f,0)+1
        # Build list
        rows = []
        for f, st in factor_stats.items():
            if st['sessions'] >= min_sessions:
                avg = st['emergence_sum']/st['sessions'] if st['sessions'] else 0.0
                sustained = self._compute_sustained_promotion(f)
                rec = {'factor': f, 'sessions': st['sessions'], 'avg_emergence': round(avg,4), 'max_emergence': round(st['max_score'],4)}
                if sustained:
                    rec.update(sustained)
                rows.append(rec)
        rows.sort(key=lambda r: (-r['avg_emergence'], -r['max_emergence'], r['factor']))
        # Metrics update
        if _PromGauge and not hasattr(self.__class__, '_promotion_candidates_gauge'):
            try:
                # Metric renamed to align with detection_ prefix in requirements
                self.__class__._promotion_candidates_gauge = _PromGauge('detection_promotion_candidates_total','Current promotion candidate count')
            except Exception:
                self.__class__._promotion_candidates_gauge = None
        if hasattr(self.__class__, '_promotion_candidates_gauge') and getattr(self.__class__,'_promotion_candidates_gauge'):
            try: self.__class__._promotion_candidates_gauge.set(len(rows))
            except Exception: pass
        # Attach tenant distribution if single candidate list requested (optional external use)
        # Build tenant distribution map for top candidates only
        top = rows[:top_n]
        tenant_dist: Dict[str, Dict[str,int]] = {}
        for cand in top:
            f = cand['factor']
            for tenant, fcounts in tenant_factor_sessions.items():
                if f in fcounts:
                    tenant_dist.setdefault(f, {})[tenant] = fcounts[f]
        for cand in top:
            td = tenant_dist.get(cand['factor'])
            if td:
                cand['tenant_distribution'] = td
        return top

    def _compute_sustained_promotion(self, factor: str) -> Dict[str, object] | None:
        """Derive sustained promotion readiness for a factor using rolling emergence history.

        Criteria (env tunable):
          - At least PROMOTION_MIN_SESSIONS scores in rolling window.
          - Average emergence >= PROMOTION_MIN_AVG_SCORE
          - Median emergence >= PROMOTION_MIN_MEDIAN_SCORE
        Returns dict with readiness details if criteria met.
        """
        hist = self._emergence_history.get(factor)
        if not hist or len(hist) < self._promotion_min_sessions:
            return None
        import statistics
        avg = sum(hist)/len(hist)
        try:
            med = statistics.median(hist)
        except Exception:
            med = avg
        if avg >= self._promotion_min_avg and med >= self._promotion_min_median:
            return {
                'promotion_ready': True,
                'emergence_avg_recent': round(avg,4),
                'emergence_median_recent': round(med,4),
                'emergence_window': len(hist)
            }
        return None

    # --- Coverage Delta Helpers ---
    def _capture_baseline_snapshot(self, max_events: int = 500) -> dict:
        try:
            from api.server import DECISION_CACHE  # type: ignore
        except Exception:
            return {'factors':{}, 'verdicts':{}, 'event_count':0}
        recent = list(DECISION_CACHE.values())[-max_events:]
        factor_counter: Counter = Counter()
        verdict_counter: Counter = Counter()
        for r in recent:
            verdict_counter[r.verdict] += 1
            for f in r.factors:
                factor_counter[f] += 1
        return {
            'factors': dict(factor_counter),
            'verdicts': dict(verdict_counter),
            'event_count': len(recent)
        }

    def _compute_coverage_delta(self, sess: HuntSession) -> dict:
        baseline = sess.baseline_snapshot or {'factors':{}, 'verdicts':{}, 'event_count':0}
        hunt_factors = sess.factors or {}
        baseline_factors = baseline['factors']
        new_factors = [f for f in hunt_factors if f not in baseline_factors]
        baseline_bad = baseline['verdicts'].get('Bad',0)
        heuristic_bad = 1 if any(k for k in hunt_factors if 'lateral' in k or 'chain' in k) else 0
        uplift_abs = heuristic_bad - baseline_bad
        uplift_pct = (uplift_abs / baseline_bad * 100.0) if baseline_bad else (100.0 if heuristic_bad>0 else 0.0)
        novelty_index = len(new_factors) / max(1,len(hunt_factors))
        # Category buckets for ROI narrative
        categories = {
            'sbom': [f for f in hunt_factors if 'sbom' in f or 'component_hash_drift' in f],
            'beacon': [f for f in hunt_factors if f.startswith('beacon_')],
            'egress': [f for f in hunt_factors if f == 'egress_volume_spike'],
            'novel_domain': [f for f in hunt_factors if f == 'new_domain_seen'],
            'rare_cmd': [f for f in hunt_factors if f.startswith('cmd_rare_token')],
        }
        return {
            'session_id': sess.id,
            'baseline_bad_count': baseline_bad,
            'hunt_bad_count_estimate': heuristic_bad,
            'uplift_bad_absolute': uplift_abs,
            'uplift_bad_percent': round(uplift_pct,2),
            'new_unique_factors': new_factors,
            'total_hunt_factors': len(hunt_factors),
            'factor_novelty_index': round(novelty_index,3),
            'baseline_event_sample': baseline.get('event_count',0),
            'category_breakdown': {k: len(v) for k,v in categories.items() if v}
        }

    # --- Factor Emergence Scoring ---
    def _compute_factor_emergence(self, sess: HuntSession) -> List[Dict[str, object]]:
        """Compute emergence score for each hunt factor relative to baseline.

        emergence_score = (hunt_freq - baseline_freq_norm) * severity_weight
        Where baseline_freq_norm = baseline_factor_count / max(1, baseline_event_sample)
        Severity bucket heuristic (MVP):
            high: factor name contains one of ['chain','lateral','priv_esc','risky'] weight 3.0
            medium: contains ['suspicious','anomal','rare'] weight 2.0
            else: weight 1.0 (low)
        """
        baseline = sess.baseline_snapshot or {'factors':{}, 'event_count':0}
        baseline_events = max(1, baseline.get('event_count',0))
        baseline_factor_counts: Dict[str,int] = baseline.get('factors',{})
        # Re-scan DECISION_CACHE to collect post-baseline occurrences (events after session start)
        try:
            from api.server import DECISION_CACHE  # type: ignore
            recent_all = list(DECISION_CACHE.values())
        except Exception:
            recent_all = []
        post_events = [r for r in recent_all if r.timestamp >= sess.start_time]
        post_event_count = max(1, len(post_events))
        hunt_factor_counts: Counter = Counter()
        for r in post_events:
            for f in r.factors:
                hunt_factor_counts[f] += 1
        hunt_factors: Dict[str,int] = dict(hunt_factor_counts)
        rows: List[Tuple[str, float, float, str, float]] = []  # (factor, hunt_occurrence_rate, baseline_norm, bucket, score)

        def bucket_and_weight(name: str) -> Tuple[str,float]:
            n = name.lower()
            if any(k in n for k in ['chain','lateral','priv_esc','risky']):
                return 'high', 3.0
            if any(k in n for k in ['suspicious','anomal','rare']):
                return 'medium', 2.0
            return 'low', 1.0

        for factor, count in hunt_factors.items():
            hunt_rate = float(count) / post_event_count
            baseline_count = float(baseline_factor_counts.get(factor,0))
            baseline_norm = baseline_count / baseline_events
            bucket, weight = bucket_and_weight(factor)
            score = (hunt_rate - baseline_norm) * weight
            rows.append((factor, hunt_rate, baseline_norm, bucket, score))

        # Sort by score descending, then by factor name
        rows.sort(key=lambda r: (-r[4], r[0]))
        out: List[Dict[str, object]] = []
        for factor, hunt_freq, baseline_norm, bucket, score in rows:
            out.append({
                'factor': factor,
                'hunt_freq': round(hunt_freq,3),
                'baseline_freq_norm': round(baseline_norm,5),
                'severity_bucket': bucket,
                'emergence_score': round(score,4),
                'freq_method': 'occurrence_rate',
                'hunt_occurrences': hunt_factors.get(factor,0)
            })
        # Append assumptions meta row (could also be separate structure)
        out.append({
            'meta': True,
            'assumptions': 'hunt_freq is occurrence rate post-session-start; baseline normalized by baseline sample events; severity heuristic via name substrings',
            'baseline_events': baseline_events,
            'post_events': post_event_count
        })
        return out

    # --- Selective Embedding Simulation ---
    def _simulate_selective_embedding(self, sess: HuntSession) -> Dict[str, object]:
        """Simulate potential suppression of high-tier escalation via semantic embeddings.

        Approach:
          - Generate synthetic similarity scores (Beta distribution approximation using simple power transform) for each factor.
          - Assume factors that would cause tier >=2 escalation are those with names containing risk markers.
          - For a grid of similarity thresholds, estimate suppression_rate = fraction of escalations whose similarity >= threshold.
          - Cost model: each embedding call costs 0.05 cost units (synthetic) when enabled.
          - Compute net_savings_units = (suppressed_escalations * escalation_unit_penalty) - (embedding_calls * embedding_unit_cost)
          - escalation_unit_penalty is approximated as 0.2 units per avoided high-tier model call.
        """
        import random, math
        factors = sess.factors or {}
        if not factors:
            return {}
        random.seed(int(sess.start_time))  # deterministic per session
        # Derive candidate escalations list
        escalation_candidates = [f for f in factors if any(k in f.lower() for k in ['chain','lateral','rare','anomal','priv_esc'])]
        if not escalation_candidates:
            return {'thresholds': [], 'note': 'no_escalation_candidates'}
        # Synthetic similarity distribution (skew high for repeated/common factors)
        sim_map: Dict[str,float] = {}
        for f in escalation_candidates:
            base = random.random()
            weight = min(1.0, max(0.05, factors.get(f,0.0)/max(1.0,sum(factors.values())) * 3))
            sim = pow(base, 1.0/(0.5+weight))  # shift distribution
            sim_map[f] = round(sim,4)
        thresholds = [0.5,0.6,0.7,0.8,0.85,0.9,0.95]
        embedding_unit_cost = 0.05
        escalation_unit_penalty = 0.2
        rows = []
        n = len(escalation_candidates)
        for th in thresholds:
            suppressed = sum(1 for s in sim_map.values() if s >= th)
            suppression_rate = suppressed / n
            embedding_calls = n  # assume embedding run for each candidate factor once
            net_savings = (suppressed * escalation_unit_penalty) - (embedding_calls * embedding_unit_cost)
            rows.append({
                'threshold': th,
                'suppression_rate': round(suppression_rate,3),
                'suppressed_escalations': suppressed,
                'embedding_calls': embedding_calls,
                'net_savings_units': round(net_savings,3)
            })
        best = max(rows, key=lambda r: r['net_savings_units']) if rows else None
        per_factor_calls = {f:1 for f in escalation_candidates}  # placeholder; future: event-level occurrences
        return {
            'candidates': escalation_candidates,
            'similarities': sim_map,
            'per_factor_calls': per_factor_calls,
            'threshold_analysis': rows,
            'best_threshold': best,
            'assumptions': 'one embedding call per escalation candidate; similarity synthetic; suppression reduces high-tier model calls (0.2 units each); embedding cost 0.05 units'
        }

_sidecar_singleton: SidecarSessionManager | None = None

def get_sidecar_manager() -> SidecarSessionManager:
    global _sidecar_singleton
    if _sidecar_singleton is None:
        _sidecar_singleton = SidecarSessionManager()
    return _sidecar_singleton
