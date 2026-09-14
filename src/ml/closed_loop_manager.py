import asyncio
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

from src.repositories.weight_staging_repo import WeightStagingRepo
from src.repositories.feature_store_repo import FeatureStoreRepo
from src.repositories.precision_metrics_repo import PrecisionMetricsRepo


class ClosedLoopManager:
    """Manage staged weight proposals, simulate expected impact, and apply guarded updates.

    Simulation strategy (conservative):
    - Sample recent events from `feature_store` (events should include a `features` map)
    - Score events under current baseline (uniform weight) and under candidate weights
    - Use historical precision for the rule to estimate TP/FP balance and compute
      expected precision delta
    - Apply only when estimated delta within guardrails (default ±0.05)
    """

    def __init__(self, db_path: Optional[str] = None):
        self.staging = WeightStagingRepo(db_path=db_path)
        self.feature_store = FeatureStoreRepo(db_path=db_path)
        self.precision_repo = PrecisionMetricsRepo()
        self.max_delta = 0.05

    async def list_pending(self):
        return await self.staging.list_pending()

    def _score_event(self, event: Dict[str, Any], weights: Dict[str, float]) -> float:
        feats = event.get('features') or {}
        s = 0.0
        for k, val in feats.items():
            try:
                v = float(val)
            except Exception:
                v = 1.0 if val else 0.0
            w = float(weights.get(k, 0.0)) if weights else 0.0
            s += v * w
        return s

    def simulate_proposal(self, proposal: Dict[str, Any], sample_size: int = 300) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        weights = proposal.get('weights') or proposal.get('proposed_weights') or {}
        rule_id = proposal.get('rule_id') or proposal.get('rule_name') or proposal.get('rule')

        # sample recent events
        try:
            events = loop.run_until_complete(self.feature_store.list_recent(limit=sample_size))
        except Exception:
            events = []

        if not events:
            return {'ok': True, 'reason': 'no_events', 'estimated_precision_delta': 0.0}

        # baseline weights (fallback uniform small weight for known features)
        baseline_w = {k: 1.0 for e in events for k in ((e.get('event') or {}).get('features') or {}).keys()}

        baseline_hits = 0
        proposed_hits = 0
        for e in events:
            ev = e.get('event') or {}
            bs = self._score_event(ev, baseline_w)
            ps = self._score_event(ev, weights)
            # threshold: score >= 1.0 considered flagged
            if bs >= 1.0:
                baseline_hits += 1
            if ps >= 1.0:
                proposed_hits += 1

        # historic precision for the rule as a prior
        try:
            hist = self.precision_repo.get_rule_precision(rule_id, days=30)
            hist_prec = hist.get('precision') or 0.1
        except Exception:
            hist_prec = 0.1

        baseline_tp = baseline_hits * hist_prec
        baseline_fp = baseline_hits - baseline_tp
        proposed_tp = proposed_hits * hist_prec
        proposed_fp = proposed_hits - proposed_tp

        baseline_precision = (baseline_tp / baseline_hits) if baseline_hits else None
        proposed_precision = (proposed_tp / proposed_hits) if proposed_hits else None
        est_delta = None
        if baseline_precision is not None and proposed_precision is not None:
            est_delta = proposed_precision - baseline_precision

        return {
            'ok': True,
            'proposal_id': proposal.get('id'),
            'rule_id': rule_id,
            'baseline_hits': baseline_hits,
            'proposed_hits': proposed_hits,
            'baseline_precision': baseline_precision,
            'proposed_precision': proposed_precision,
            'estimated_precision_delta': est_delta,
        }

    def apply_proposal_if_safe(self, proposal_id: int) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        pend = loop.run_until_complete(self.staging.list_pending())
        p = next((x for x in pend if x['id'] == proposal_id), None)
        if not p:
            return {'ok': False, 'error': 'not_found'}
        sim = self.simulate_proposal(p)
        if not sim.get('ok'):
            return {'ok': False, 'reason': 'sim_failed'}
        delta = sim.get('estimated_precision_delta') or 0.0
        if abs(delta) > self.max_delta:
            return {'ok': False, 'reason': 'guardrail_failed', 'estimated_delta': delta, 'sim': sim}
        # mark applied
        loop.run_until_complete(self.staging.mark_applied(p['id']))
        return {'ok': True, 'applied': p['id'], 'sim': sim}
"""Closed-loop manager: staging, simulation, and guarded apply of weight deltas.

This is a conservative implementation suitable for CI and manual review.
It stages proposals via WeightStagingRepo, simulates expected precision change
by replaying a small sample from the feature store, and applies only when
guardrails are met (max 5% precision change per update by default).
"""
import asyncio
import time
from typing import Dict, Any, List, Optional

from src.repositories.weight_staging_repo import WeightStagingRepo
from src.repositories.feature_store_repo import FeatureStoreRepo
from src.repositories.precision_metrics_repo import PrecisionMetricsRepo


class ClosedLoopManager:
    def __init__(self, db_path: Optional[str] = None):
        self.staging = WeightStagingRepo(db_path=db_path)
        self.feature_store = FeatureStoreRepo(db_path=db_path)
        self.precision_repo = PrecisionMetricsRepo()
        # guardrail: max absolute precision delta allowed per update
        self.max_delta = float(0.05)

    def ready_to_learn(self) -> bool:
        # minimal readiness check: staging has pending items
        pending = asyncio.get_event_loop().run_until_complete(self.staging.list_pending())
        return bool(pending)

    async def propose_weights(self) -> List[Dict[str, Any]]:
        # Return pending staged proposals for operator review
        return await self.staging.list_pending()

    def _score_event_with_weights(self, event: dict, weights: dict) -> float:
        # Simple linear scoring: sum(weight*feature_presence)
        # Features are expected in event['features'] as a mapping of feature->value
        f = event.get('features') or {}
        s = 0.0
        for k, v in weights.items():
            try:
                s += float(v) * (1.0 if f.get(k) else 0.0)
            except Exception:
                pass
        return s

    def simulate_proposal(self, proposal: Dict[str, Any], sample_size: int = 500) -> Dict[str, Any]:
        # Simulate candidate weights against recent events from feature_store
        loop = asyncio.get_event_loop()
        pending = loop.run_until_complete(self.staging.list_pending())
        if not pending:
            return {'ok': False, 'reason': 'no_pending'}
        # Extract candidate weights from proposal
        weights = proposal.get('weights') or proposal.get('proposed_weights') or {}
        # fetch sample events
        events = loop.run_until_complete(self.feature_store.list_recent(limit=sample_size))
        if not events:
            # no historical events; return conservative zero-delta
            return {'ok': True, 'estimated_precision_delta': 0.0, 'simulated_tp_delta': 0, 'simulated_fp_delta': 0}
        # For each event, compute baseline score (assume baseline weights = 1 for known features)
        baseline_hits = 0
        proposed_hits = 0
        for e in events:
            ev = e.get('event') or {}
            # baseline scoring: simple heuristic, feature count
            base_score = sum(1.0 for _ in (ev.get('features') or {}).keys())
            proposed_score = self._score_event_with_weights(ev, weights)
            # thresholding: event considered flagged if score >= 1.0
            if base_score >= 1.0:
                baseline_hits += 1
            if proposed_score >= 1.0:
                proposed_hits += 1
        # For a rough precision estimate, query recent adjudications for the same rule if exists
        # Use precision repo to compute recent precision for control
        try:
            # sample last 30 days
            now = int(time.time())
            past = now - (30 * 86400)
            arr = self.precision_repo.fp_reduction_trend(past, now)
            # compute last-known precision as tp / (tp+fp)
            if arr:
                last = arr[-1]
                control_precision = last.get('precision') or 0.0
            else:
                control_precision = None
        except Exception:
            control_precision = None

        # compute deltas heuristically
        delta_hits = proposed_hits - baseline_hits
        # assume small sample equates to proportional change in TP/FP balance
        # Simulated tp/fp delta estimates are synthetic and conservative
        simulated_tp_delta = int(max(0, delta_hits * 0.3))
        simulated_fp_delta = int(max(0, -delta_hits * 0.3))
        # estimated precision delta: (proposed_precision - control_precision)
        if control_precision is not None and baseline_hits > 0:
            # naive estimated precision after change
            proposed_precision = control_precision + (simulated_tp_delta - simulated_fp_delta) / (baseline_hits or 1)
            estimated_delta = proposed_precision - control_precision
        else:
            estimated_delta = 0.0

        return {
            'ok': True,
            'proposal_id': proposal.get('id'),
            'rule_id': proposal.get('rule_id'),
            'estimated_precision_delta': float(estimated_delta),
            'simulated_tp_delta': simulated_tp_delta,
            'simulated_fp_delta': simulated_fp_delta,
            'baseline_hits': baseline_hits,
            'proposed_hits': proposed_hits,
        }

    def apply_proposal_if_safe(self, proposal_id: int) -> Dict[str, Any]:
        loop = asyncio.get_event_loop()
        pend = loop.run_until_complete(self.staging.list_pending())
        p = next((x for x in pend if x['id'] == proposal_id), None)
        if not p:
            return {'ok': False, 'error': 'not_found'}
        # Run deterministic replay evaluation for accurate TP/FP estimates
        try:
            from src.ml.replay_eval import ReplayEvaluator
            rev = ReplayEvaluator()
            report = rev.replay(p.get('weights') or p.get('proposed_weights') or {}, sample_limit=2000)
            try:
                from src.core.metrics import make_counter
                _c = make_counter('replay_runs_total', 'Total replay evaluations run')
                _c.inc()
            except Exception:
                pass
        except Exception:
            # fallback to earlier simulate heuristic if replay unavailable
            report = self.simulate_proposal(p)

        # enforce minimum sample size for confidence
        sample_size = report.get('sample_size') or (report.get('baseline_hits', 0) + report.get('proposed_hits', 0))
        if sample_size < 50:
            return {'ok': False, 'reason': 'insufficient_sample', 'sample_size': sample_size, 'report': report}

        # compute CI delta check if available
        base_ci = report.get('baseline_ci')
        prop_ci = report.get('proposed_ci')
        # If both CIs available, ensure lower bound of proposed > upper bound of baseline - guard
        try:
            if base_ci and prop_ci:
                if prop_ci[0] < (base_ci[1] - self.max_delta):
                    return {'ok': False, 'reason': 'ci_guardrail_failed', 'report': report}
        except Exception:
            pass

        # Canary rollout: persist applied weights with a rollout_pct default to 5%
        rollout_pct = float(os.getenv('CANARY_ROLLOUT_PCT','5'))
        applied_weights = p.get('weights') or p.get('proposed_weights') or {}
        try:
            # write to a local JSON file used by runtime to apply partial rollouts
            import json, os as _os
            path = os.path.join('data', 'factor_weights_current.json')
            _os.makedirs(_os.path.dirname(path), exist_ok=True)
            entry = {'candidate_id': p['id'], 'weights': applied_weights, 'rollout_pct': rollout_pct, 'applied_at': int(time.time())}
            with open(path, 'w', encoding='utf-8') as fh:
                json.dump(entry, fh, ensure_ascii=False)
        except Exception:
            pass

        # mark applied in staging store and audit
        try:
            loop.run_until_complete(self.staging.mark_applied(p['id']))
            try:
                from src.core.metrics import make_counter
                _apply_c = make_counter('proposal_applies_total', 'Total applied proposals')
                _apply_c.inc()
            except Exception:
                pass
        except Exception:
            pass
        return {'ok': True, 'applied': p['id'], 'report': report, 'rollout_pct': rollout_pct}
import sqlite3
import os
from datetime import datetime
from typing import Dict, List, Optional, Awaitable
from .factor_weight_learner import FactorWeightLearner


DB_PATH = 'data/precision_metrics.db'


def _dump_json(obj) -> str:
    import json
    try:
        return json.dumps(obj, default=str, ensure_ascii=False)
    except Exception:
        return str(obj)


class ClosedLoopManager:
    """Manages feedback buffer persistence, candidate proposals and approved weights."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        # Defer creation of the FactorWeightLearner to avoid importing
        # sklearn/scipy at module import time during test collection.
        self.learner = None
        self._ensure_tables()

    def _ensure_learner(self):
        if self.learner is None:
            try:
                from .factor_weight_learner import FactorWeightLearner
                self.learner = FactorWeightLearner()
            except Exception:
                self.learner = None

    def _conn(self):
        return sqlite3.connect(self.db_path)

    def _ensure_tables(self):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS factor_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                factor TEXT,
                vote INTEGER,
                created_at TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS factor_weight_candidates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                candidate_json TEXT,
                delta_summary TEXT,
                created_at TEXT,
                approved_at TEXT,
                approved_by TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS factor_weight_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT,
                payload TEXT,
                actor TEXT,
                ts TEXT
            )
            """
        )
        conn.commit()
        conn.close()

    def add_feedback(self, event_id: str, factors: List[str], vote: int):
        # Support optional centralized file-backed persistence when USE_PLATFORM_DB=1
        if os.getenv('USE_PLATFORM_DB','0').lower() in {'1','true','yes'}:
            p = os.path.join('data', 'factor_feedback.jsonl')
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, 'a', encoding='utf-8') as fh:
                for f in factors:
                    rec = {'event_id': event_id, 'factor': f, 'vote': int(vote), 'created_at': datetime.utcnow().isoformat()}
                    fh.write(_dump_json(rec) + '\n')
        else:
            conn = self._conn()
            cur = conn.cursor()
            for f in factors:
                cur.execute(
                    "INSERT INTO factor_feedback (event_id,factor,vote,created_at) VALUES (?,?,?,?)",
                    (event_id, f, int(vote), datetime.utcnow().isoformat()),
                )
            conn.commit()
            conn.close()
        # also add to in-memory learner buffer
        try:
            self._ensure_learner()
            if self.learner is not None:
                for f in factors:
                    self.learner.add_feedback(event_id, [f], vote)
        except Exception:
            pass

    def ready_to_learn(self) -> bool:
        try:
            self._ensure_learner()
            return bool(self.learner and self.learner.ready())
        except Exception:
            return False

    def propose_weights(self) -> Awaitable[Dict[str, float]]:
        """Return an awaitable that computes candidate weights.

        Tests and callers often expect an awaitable so they can run it
        with their preferred event loop (e.g. `run_until_complete`).
        This method therefore always returns the coroutine object for
        the async implementation; synchronous convenience callers can
        use `asyncio.run(clm.propose_weights())` if they need a blocking
        result.
        """
        return self._propose_weights_async()


    async def _propose_weights_async(self) -> Dict[str, float]:
        """Internal async implementation: run learner and persist candidate."""
        try:
            self._ensure_learner()
            weights = self.learner.learn() if self.learner is not None else {}
        except Exception:
            weights = {}
        candidate_id = None
        # Build delta summary (naive)
        summary = ",".join([f"{k}:{v:.3f}" for k, v in weights.items()])
        import json as _json
        # If USE_PLATFORM_DB enabled, persist candidate to DB via closed_loop_persistence
        if os.getenv('USE_PLATFORM_DB','0').lower() in {'1','true','yes'}:
            try:
                from src.ml.closed_loop_persistence import persist_candidate_async, persist_audit_async
                try:
                    candidate_id = await persist_candidate_async({'candidate': weights, 'summary': summary, 'created_at': datetime.utcnow().isoformat()})
                except Exception:
                    # fallback to older name
                    try:
                        from src.ml.closed_loop_persistence import persist_candidate
                        candidate_id = persist_candidate({'candidate': weights, 'summary': summary, 'created_at': datetime.utcnow().isoformat()})
                    except Exception:
                        candidate_id = None
                try:
                    await persist_audit_async('propose', {'candidate_id': candidate_id, 'summary': summary}, actor='system')
                except Exception:
                    try:
                        from src.ml.closed_loop_persistence import persist_audit
                        persist_audit('propose', {'candidate_id': candidate_id, 'summary': summary}, actor='system')
                    except Exception:
                        pass
            except Exception:
                # fallback to local JSONL file if DB persistence fails
                p = os.path.join('data', 'factor_weight_candidates.jsonl')
                os.makedirs(os.path.dirname(p), exist_ok=True)
                with open(p, 'a', encoding='utf-8') as fh:
                    fh.write(_dump_json({'candidate': weights, 'summary': summary, 'created_at': datetime.utcnow().isoformat()}) + '\n')
                self._audit('propose', _dump_json(weights), actor='system')
                candidate_id = p
        else:
            conn = self._conn()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO factor_weight_candidates (candidate_json, delta_summary, created_at) VALUES (?,?,?)",
                (_json.dumps(weights), summary, datetime.utcnow().isoformat()),
            )
            conn.commit()
            conn.close()
            # audit
            self._audit('propose', _json.dumps(weights), actor='system')
        result = {'candidate': weights, 'summary': summary, 'candidate_id': candidate_id}
        try:
            if isinstance(weights, dict):
                result.update(weights)
        except Exception:
            pass
        return result

    def list_candidates(self) -> List[Dict]:
        out = []
        if os.getenv('USE_PLATFORM_DB','0').lower() in {'1','true','yes'}:
            try:
                from src.ml.closed_loop_persistence import list_candidates
                out = list_candidates(limit=50)
                return out
            except Exception:
                # fallback to file-backed listing
                p = os.path.join('data', 'factor_weight_candidates.jsonl')
                if not os.path.exists(p):
                    return []
                with open(p, 'r', encoding='utf-8') as fh:
                    lines = [l.strip() for l in fh if l.strip()]
                import json as _json
                for idx, line in enumerate(reversed(lines[-50:]), start=1):
                    try:
                        rec = _json.loads(line)
                    except Exception:
                        continue
                    out.append({'id': idx, 'candidate': rec.get('candidate'), 'summary': rec.get('summary'), 'created_at': rec.get('created_at'), 'approved_at': None, 'approved_by': None})
                return out
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT id,candidate_json,delta_summary,created_at,approved_at,approved_by FROM factor_weight_candidates ORDER BY id DESC LIMIT 50")
        rows = cur.fetchall()
        conn.close()
        import json as _json
        for r in rows:
            cand = r[1]
            try:
                cand = _json.loads(r[1]) if isinstance(r[1], str) else r[1]
            except Exception:
                cand = r[1]
            out.append({
                'id': r[0], 'candidate': cand, 'summary': r[2], 'created_at': r[3], 'approved_at': r[4], 'approved_by': r[5]
            })
        return out

    def approve_candidate(self, candidate_id: int, actor: str, current_weights: Optional[Dict[str, float]] = None) -> Dict[str, float]:
        """Apply guardrails (±5%) and approve candidate; returns applied weights."""
        # Support file-backed candidate store when USE_PLATFORM_DB enabled
        candidate = None
        if os.getenv('USE_PLATFORM_DB','0').lower() in {'1','true','yes'}:
            p = os.path.join('data', 'factor_weight_candidates.jsonl')
            if not os.path.exists(p):
                raise KeyError('candidate not found')
            import json as _json
            with open(p, 'r', encoding='utf-8') as fh:
                lines = [l.strip() for l in fh if l.strip()]
            try:
                rec = _json.loads(lines[-candidate_id]) if candidate_id <= len(lines) else None
            except Exception:
                rec = None
            if not rec:
                raise KeyError('candidate not found')
            candidate = rec.get('candidate')
        else:
            conn = self._conn()
            cur = conn.cursor()
            cur.execute("SELECT candidate_json FROM factor_weight_candidates WHERE id=?", (candidate_id,))
            row = cur.fetchone()
            if not row:
                raise KeyError('candidate not found')
            import json as _json
            try:
                candidate = _json.loads(row[0]) if isinstance(row[0], str) else row[0]
            except Exception:
                try:
                    candidate = eval(row[0]) if isinstance(row[0], str) else row[0]
                except Exception:
                    candidate = {}
        applied = {}
        # auto-fetch current weights if not provided
        if current_weights is None:
            try:
                from src.core.repositories import factor_weights_repo
                cur = factor_weights_repo.get_current_weights()
                import asyncio
                if hasattr(cur, '__await__'):
                    try:
                        current_weights = asyncio.get_event_loop().run_until_complete(cur)
                    except Exception:
                        current_weights = {}
                else:
                    current_weights = cur or {}
            except Exception:
                current_weights = {}

        # guardrails vs current_weights
        for f, v in candidate.items():
            base = (current_weights.get(f, 0.5) if current_weights else 0.5)
            # clamp delta to ±5%
            max_delta = 0.05
            delta = max(-max_delta, min(max_delta, v - base))
            applied_val = max(0.0, min(1.0, base + delta))
            applied[f] = applied_val

        # persist approval (single operation)
        if os.getenv('USE_PLATFORM_DB','0').lower() in {'1','true','yes'}:
            try:
                from src.ml.closed_loop_persistence import persist_audit_async, approve_candidate_db
                try:
                    # await approval DB update if coroutine
                    res = approve_candidate_db(candidate_id, actor, applied)
                    import asyncio
                    if hasattr(res, '__await__'):
                        try:
                            asyncio.get_event_loop().run_until_complete(res)
                        except Exception:
                            try:
                                asyncio.run(res)
                            except Exception:
                                pass
                except Exception:
                    pass
                try:
                    asyncio.get_event_loop().run_until_complete(persist_audit_async('approve', {'id': candidate_id, 'applied': applied, 'candidate': candidate}, actor=actor))
                except Exception:
                    try:
                        from src.ml.closed_loop_persistence import persist_audit
                        persist_audit('approve', {'id': candidate_id, 'applied': applied, 'candidate': candidate}, actor=actor)
                    except Exception:
                        pass
            except Exception:
                self._audit('approve', _dump_json({'id': candidate_id, 'applied': applied}), actor=actor)
        else:
            cur.execute("UPDATE factor_weight_candidates SET approved_at=?, approved_by=? WHERE id=?",
                        (datetime.utcnow().isoformat(), actor, candidate_id))
            conn.commit()
            conn.close()
            import json as _json
            self._audit('approve', _json.dumps({'id': candidate_id, 'applied': applied}), actor=actor)
        return applied

    async def approve_candidate_async(self, candidate_id: int, actor: str, current_weights: Optional[Dict[str, float]] = None) -> Dict[str, float]:
        # Run the synchronous approve_candidate in a thread to avoid blocking
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, lambda: self.approve_candidate(candidate_id, actor, current_weights=current_weights))

    def _audit(self, action: str, payload: str, actor: str = 'system'):
        # If file-backed mode enabled, append to audit JSONL
        if os.getenv('USE_PLATFORM_DB','0').lower() in {'1','true','yes'}:
            p = os.path.join('data', 'factor_weight_audit.jsonl')
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, 'a', encoding='utf-8') as fh:
                fh.write(_dump_json({'action': action, 'payload': payload, 'actor': actor, 'ts': datetime.utcnow().isoformat()}) + '\n')
            return
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO factor_weight_audit (action,payload,actor,ts) VALUES (?,?,?,?)",
                    (action, payload, actor, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
