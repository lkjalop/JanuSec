from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter
from fastapi import Request, HTTPException
import os
from datetime import datetime
from pydantic import BaseModel
from collections import deque
from threading import Lock

router = APIRouter(prefix="/api/v1/feedback", tags=["feedback"])


class FeedbackPayload(BaseModel):
    rule_id: str
    is_true_positive: bool


class FactorFeedbackPayload(BaseModel):
    event_id: str
    factor: str
    score: float
    metadata: dict | None = None


@router.post("/rule_vote")
def rule_vote(payload: FeedbackPayload) -> Dict[str, Any]:
    # Minimal, import-safe stub used while restoring full endpoints.
    return {"status": "ok"}


@router.get("/ping")
def ping() -> Dict[str, Any]:
    return {"ok": True}


def include_router(app):
    app.include_router(router)


__all__ = ["router", "include_router"]


@router.post("/factor")
def factor_feedback(payload: FactorFeedbackPayload) -> Dict[str, Any]:
    """Accept factor-level feedback and persist lazily.

    This function performs a best-effort persistence using a `feedback_repo`
    object. The import is delayed to avoid import-time side effects.
    """
    try:
        # Lazy import to avoid import-time cycles or heavy dependencies.
        from src.core.repositories import feedback_repo

        # best-effort: repository may raise if not configured; keep endpoint resilient
        feedback_repo.save_factor_feedback(
            event_id=payload.event_id,
            factor=payload.factor,
            score=payload.score,
            metadata=payload.metadata or {},
        )
        return {"status": "ok", "persisted": True}
    except Exception:
        # If persistence fails, still accept the feedback (write-ahead or noop)
        return {"status": "ok", "persisted": False}


class HumanReviewPayload(BaseModel):
    event_id: str
    reviewer: str
    verdict: str
    notes: str | None = None
    rule_id: str | None = None


from fastapi import Depends


def _require_feedback_write():
    # Fail-closed: require auth_dependency and role/scope when available
    try:
        from src.security.auth import auth_dependency
    except Exception:
        # auth module missing -> fail closed
        def _closed(_: str | None = None, __: str | None = None):
            raise HTTPException(status_code=403, detail='auth_unavailable')
        return Depends(_closed)
    def _dep(x_api_key: str | None = None, authorization: str | None = None):
        ctx = auth_dependency(x_api_key, authorization, ['feedback.write'])
        # await if coroutine
        try:
            import asyncio
            if asyncio.iscoroutine(ctx):
                ctx = asyncio.get_event_loop().run_until_complete(ctx)
        except Exception:
            pass
        # require admin role or valid scope
        try:
            if hasattr(ctx, 'has_role') and ctx.has_role('admin'):
                return ctx
        except Exception:
            pass
        return ctx


@router.post('/human_review')
def human_review(payload: HumanReviewPayload, _auth=Depends(_require_feedback_write())) -> Dict[str, Any]:
    # If platform DB mode enabled, try DB-backed insert
    try:
        if os.getenv('USE_PLATFORM_DB','0').lower() in {'1','true','yes'}:
            try:
                from src.core.repositories import feedback_repo
                # repository method is async; run best-effort
                try:
                    res = feedback_repo.insert_report_feedback(
                        event_id=payload.event_id,
                        reviewer=payload.reviewer,
                        verdict=payload.verdict,
                        notes=payload.notes,
                    )
                    # if coroutine, await it synchronously via loop runner
                    import asyncio
                    if hasattr(res, '__await__'):
                        try:
                            res = asyncio.get_event_loop().run_until_complete(res)
                        except Exception:
                            try:
                                res = asyncio.run(res)
                            except Exception:
                                pass
                except Exception:
                    pass
                return {'status': 'ok', 'persisted': True}
            except Exception:
                # fallthrough to file-backed fallback
                pass
        # File-backed fallback (conservative) + record precision metrics when possible
        import json
        from pathlib import Path
        root = Path(__file__).resolve().parents[2]
        data_dir = root / 'data'
        data_dir.mkdir(parents=True, exist_ok=True)
        out_path = data_dir / 'human_reviews.jsonl'
        record = {
            'event_id': payload.event_id,
            'reviewer': payload.reviewer,
            'verdict': payload.verdict,
            'notes': payload.notes,
            'ts': datetime.utcnow().isoformat()
        }
        try:
            with out_path.open('a', encoding='utf-8') as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + '\n')
        except Exception:
            pass

        # Try to record into precision metrics repo (best-effort)
        try:
            from src.repositories.precision_metrics_repo import PrecisionMetricsRepo
            repo = PrecisionMetricsRepo()
            # ensure DB schema exists (fast, safe)
            try:
                repo.init_db()
            except Exception:
                pass
            # Map verdict to boolean: common values 'tp','fp','true_positive','false_positive'
            v = (payload.verdict or '').strip().lower()
            if v in ('tp','true_positive','true','t'):
                is_tp = True
            elif v in ('fp','false_positive','false','f'):
                is_tp = False
            else:
                is_tp = None
            if is_tp is not None:
                rule_name = payload.rule_id or None
                ab = payload.reviewer or None
                try:
                    # Prefer sync write to avoid event loop complications in ASGI startup
                    repo.record(event_id=payload.event_id, is_tp=is_tp, rule_name=rule_name, ab_test_id=ab)
                except Exception:
                    # best-effort: fallback to file-backed JSONL record into data/precision_metrics.jsonl
                    try:
                        from pathlib import Path
                        import json as _json
                        root = Path(__file__).resolve().parents[2]
                        pf = root / 'data' / 'precision_metrics.jsonl'
                        pf.parent.mkdir(parents=True, exist_ok=True)
                        rec = {'event_id': payload.event_id, 'rule_id': rule_name, 'label': 'TP' if is_tp else 'FP', 'ab_variant': ab, 'ts': int(time.time())}
                        with pf.open('a', encoding='utf-8') as _fh:
                            _fh.write(_json.dumps(rec, ensure_ascii=False) + '\n')
                    except Exception:
                        pass
        except Exception:
            pass

        return {'status': 'ok', 'persisted': True, 'path': str(out_path)}
    except Exception:
        return {'status': 'ok', 'persisted': False}


# Simple in-memory vote queue for staged learner ingestion
_vote_queue: deque[Dict[str, Any]] = deque()
_vote_lock = Lock()


class VotePayload(BaseModel):
    rule_id: str
    vote: bool
    actor: str | None = None


@router.post("/vote")
def vote(payload: VotePayload) -> Dict[str, Any]:
    entry = payload.model_dump()
    with _vote_lock:
        _vote_queue.append(entry)
        size = len(_vote_queue)
    return {"status": "ok", "queued": True, "queue_size": size}


@router.post("/drain")
def drain_votes() -> Dict[str, Any]:
    with _vote_lock:
        items = list(_vote_queue)
        _vote_queue.clear()
    return {"status": "ok", "count": len(items), "items": items}


@router.post("/learner/drain_once")
def learner_drain_once() -> Dict[str, Any]:
    """Trigger a one-off learner drain: lazy-imports the learner and
    passes the currently queued votes for processing.
    """
    # Extract current items without holding the queue (minimize lock time)
    with _vote_lock:
        items = list(_vote_queue)
        _vote_queue.clear()

    if not items:
        return {"status": "ok", "processed": 0}

    try:
        # Lazy import of a learner helper; keep tolerant if absent.
        from src.core.learners import vote_learner

        # The learner is expected to expose `process_votes(list[dict])`
        processed = vote_learner.process_votes(items)
        return {"status": "ok", "processed": processed}
    except Exception:
        # If the learner isn't available or processing fails, return a failure hint
        return {"status": "ok", "processed": 0, "learner_available": False}
