"""Assessment persistence layer for the deep-analysis pipeline.

Owns the two in-memory stores (REPORT_STORE, PARENT_CHILD_INDEX) and the
four functions that read/write them. All external callers that currently
import these symbols from src.api.deep_analyze_endpoints continue to work
via the re-export shim in that module.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
import threading

from src.api.persist_utils import atomic_write_json

logger = logging.getLogger(__name__)


class _BoundedDict(dict):
    """Thread-safe dict with a FIFO size cap.

    REPORT_STORE holds one full assessment object per id. Before the Phase A
    refactor it was a bounded dict; the refactor replaced it with a plain dict,
    so a long-running server grew it without limit (latent OOM). This restores
    the cap.

    Semantics:
      - inserting a NEW key when at capacity evicts the OLDEST key (insertion
        order); updating an EXISTING key keeps its position and never evicts.
      - on eviction, if the evicted value carries a ``persisted_path`` it is
        flushed to disk first, so reads can still recover it via the disk
        fallback in ``_get_assessment_cached`` (write-through safety).
      - ``items()`` returns a list snapshot so concurrent writers can't mutate
        an iterator mid-loop.
    """

    def __init__(self, *args, maxsize: int = 1024, **kwargs):
        self._maxsize = max(1, int(maxsize))
        self._lock = threading.RLock()
        super().__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        with self._lock:
            existing = key in self
            super().__setitem__(key, value)
            if not existing and len(self) > self._maxsize:
                oldest = next(iter(self))
                self._flush_on_evict(oldest, super().get(oldest))
                super().__delitem__(oldest)

    def items(self):
        with self._lock:
            return list(super().items())

    @staticmethod
    def _flush_on_evict(key, value) -> None:
        try:
            if isinstance(value, dict) and value.get('persisted_path'):
                atomic_write_json(value['persisted_path'], value)
        except Exception:
            logger.debug('REPORT_STORE evict flush failed for %s', key)


# Primary in-memory assessment store: assessment_id → assessment dict.
# Bounded so a long-running process can't grow it unbounded; persisted entries
# remain recoverable from disk after eviction.
_REPORT_STORE_MAX = int(os.getenv('JANUSEC_REPORT_STORE_MAX', '1024') or 1024)
REPORT_STORE: dict[str, dict] = _BoundedDict(maxsize=_REPORT_STORE_MAX)

# Parent → [child_assessment_id, ...] index for batch/split assessments.
PARENT_CHILD_INDEX: dict[str, list[str]] = {}


def _persist_assessment_state(assessment_id: str, assessment: dict) -> None:
    if not assessment_id or not isinstance(assessment, dict):
        return
    REPORT_STORE[assessment_id] = assessment
    path = assessment.get('persisted_path')
    if path:
        try:
            atomic_write_json(path, assessment)
        except Exception as _exc:
            logger.debug('silent_swallow at %s:%d: %s', __file__, 36, _exc)


def _get_assessment_cached(assessment_id: str) -> dict | None:
    assessment = REPORT_STORE.get(assessment_id)
    if assessment:
        return assessment

    # Try the standard disk loader first
    disk = _load_assessment_from_disk(assessment_id, None)
    if disk:
        REPORT_STORE[assessment_id] = disk
        return disk

    # Fallback: scan the SESSION_PERSIST_DIR for any file starting with the assessment_id
    try:
        repo_root = os.getcwd()
        base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
        index_dir = os.path.join(base, 'index')
        idx_path = os.path.join(index_dir, f"{assessment_id}.path")
        if os.path.exists(idx_path):
            try:
                with open(idx_path, 'r', encoding='utf-8') as fh:
                    p = fh.read().strip()
                if p and os.path.exists(p):
                    with open(p, 'r', encoding='utf-8') as fh:
                        disk2 = json.load(fh)
                    REPORT_STORE[assessment_id] = disk2
                    return disk2
            except Exception as _exc:
                logger.debug('silent_swallow at %s:%d: %s', __file__, 69, _exc)
        if os.path.isdir(base):
            for root, _dirs, files in os.walk(base):
                for f in files:
                    if f.startswith(str(assessment_id)) and f.endswith('.json'):
                        path = os.path.join(root, f)
                        try:
                            with open(path, 'r', encoding='utf-8') as fh:
                                disk2 = json.load(fh)
                            REPORT_STORE[assessment_id] = disk2
                            return disk2
                        except Exception:
                            continue
        # Final content scan is intentionally opt-in. On local demo machines
        # data/assessments can contain large acceptance artifacts, and a 404
        # lookup should not open every JSON file in that tree.
        if str(os.getenv('ASSESSMENT_CONTENT_SCAN_FALLBACK') or '').lower() in {'1', 'true', 'yes'}:
            try:
                for root, _dirs, files in os.walk(base):
                    for f in files:
                        if not f.endswith('.json'):
                            continue
                        path = os.path.join(root, f)
                        try:
                            with open(path, 'r', encoding='utf-8') as fh:
                                cand = json.load(fh)
                            if isinstance(cand, dict) and str(cand.get('assessment_id') or '') == str(assessment_id):
                                REPORT_STORE[assessment_id] = cand
                                return cand
                        except Exception:
                            continue
            except Exception as _exc:
                logger.debug('silent_swallow at %s:%d: %s', __file__, 97, _exc)
    except Exception as _exc:
        logger.debug('silent_swallow at %s:%d: %s', __file__, 99, _exc)
    return None


def _write_assessment_index(assessment_id: str, persisted_path: str) -> None:
    try:
        repo_root = os.getcwd()
        base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
        index_dir = os.path.join(base, 'index')
        os.makedirs(index_dir, exist_ok=True)
        idx_path = os.path.join(index_dir, f"{assessment_id}.path")
        tmp = idx_path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            fh.write(persisted_path)
        os.replace(tmp, idx_path)
    except Exception as _exc:
        logger.debug('silent_swallow at %s:%d: %s', __file__, 113, _exc)


def _load_assessment_from_disk(assessment_id: str, preferred_path: str | None = None):
    candidates = []
    if preferred_path:
        candidates.append(preferred_path)
    try:
        repo_root = os.getcwd()
        base = os.getenv('SESSION_PERSIST_DIR') or os.path.join(repo_root, 'data', 'assessments')
        if os.path.isdir(base):
            dates = [datetime.datetime.utcnow().strftime('%Y-%m-%d')]
            dates.append((datetime.datetime.utcnow() - datetime.timedelta(days=1)).strftime('%Y-%m-%d'))
            for d in dates:
                for orgdir in os.listdir(base):
                    p = os.path.join(base, orgdir, d, f"{assessment_id}.json")
                    candidates.append(p)
    except Exception as _exc:
        logger.debug('silent_swallow at %s:%d: %s', __file__, 129, _exc)
    for path in candidates:
        if not path:
            continue
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    return json.load(fh)
            except Exception:
                continue
    return None
