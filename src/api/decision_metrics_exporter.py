"""Background exporter that reads the decision audit store and exposes
a gauge of open / pending decisions for Prometheus."""
from __future__ import annotations
import os, time, json, logging
from typing import Any
from src.api.metrics_init import ensure_metrics, _safe_gauge

logger = logging.getLogger(__name__)
ensure_metrics()
pending_decisions_gauge = _safe_gauge('decision_pending_gauge', 'Count of pending/unresolved decisions')

AUDIT_DIR = os.getenv('SESSION_PERSIST_DIR') or os.path.join(os.getcwd(), 'data', 'sessions')
AUDIT_PATH = os.path.join(AUDIT_DIR, 'decision_audit.json')


def _load_audit() -> dict:
    try:
        if os.path.exists(AUDIT_PATH):
            with open(AUDIT_PATH, 'r', encoding='utf-8') as fh:
                return json.load(fh) or {}
    except Exception:
        pass
    return {}


def update_pending_gauge():
    try:
        audit = _load_audit()
        decs = audit.get('decisions', {}) or {}
        pending = 0
        for gid, rec in decs.items():
            d = rec.get('decision', {}) or {}
            # consider pending if no decision_made or status not approved/executed
            if not d.get('decision_made'):
                pending += 1
        try:
            pending_decisions_gauge.set(pending)
        except Exception:
            try:
                pending_decisions_gauge.labels().set(pending)
            except Exception:
                pass
        return pending
    except Exception as e:
        logger.exception('Failed to update pending decisions gauge: %s', e)
        return 0
