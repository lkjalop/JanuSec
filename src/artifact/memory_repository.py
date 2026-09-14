from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


class MemoryJobStore:
    """Persist memory job metadata for enrichment, Multi-Domain correlator, and UI evidence panes."""

    def __init__(self, path: str | Path = "data/memory_jobs/index.jsonl", *, max_cached: int = 2000) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_cached = max_cached
        self._lock = threading.RLock()
        self._jobs: List[Dict[str, Any]] = []
        self._load_existing()

    def _load_existing(self) -> None:
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._jobs.append(payload)
            if len(self._jobs) > self.max_cached:
                self._jobs = self._jobs[-self.max_cached :]
        except Exception:
            self._jobs = []

    def record_job(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Persist a normalized job payload and return it."""
        payload = dict(payload)
        payload.setdefault("recorded_at", time.time())
        job_id = payload.get("job_id")
        with self._lock:
            if job_id:
                self._jobs = [job for job in self._jobs if job.get("job_id") != job_id]
            self._jobs.append(payload)
            if len(self._jobs) > self.max_cached:
                self._jobs = self._jobs[-self.max_cached :]
            try:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(payload, separators=(",", ":")) + "\n")
            except Exception:
                pass
        return payload

    def _filter_jobs(
        self,
        *,
        host: Optional[str],
        case_id: Optional[str],
        tenant_id: Optional[str],
        limit: int,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        host_norm = host.lower().strip() if host else None
        case_norm = case_id.lower().strip() if case_id else None
        tenant_norm = tenant_id.lower().strip() if tenant_id else None
        with self._lock:
            for job in reversed(self._jobs):
                if host_norm and job.get("host") != host_norm:
                    continue
                if case_norm and job.get("case_id") != case_norm:
                    continue
                job_tenant = (job.get("tenant_id") or "").lower()
                if tenant_norm and job_tenant and job_tenant != tenant_norm:
                    continue
                results.append(job)
                if len(results) >= limit:
                    break
        return results

    def recent(
        self,
        *,
        host: Optional[str] = None,
        case_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        return self._filter_jobs(host=host, case_id=case_id, tenant_id=tenant_id, limit=max(1, limit))

    def recent_for_entities(
        self, entities: Iterable[str], *, limit: int = 5, tenant_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        seen: set[str] = set()
        collected: List[Dict[str, Any]] = []
        for entity in entities:
            if not entity:
                continue
            for job in self.recent(host=entity, tenant_id=tenant_id, limit=limit):
                job_id = job.get("job_id")
                if job_id and job_id in seen:
                    continue
                seen.add(job_id)
                collected.append(job)
                if len(collected) >= limit:
                    return collected
        return collected


def _default_store_path() -> Path:
    env_path = os.getenv("MEMORY_JOB_STORE_PATH")
    return Path(env_path) if env_path else Path("data/memory_jobs/index.jsonl")


MEMORY_JOB_STORE = MemoryJobStore(_default_store_path())


def normalize_job_payload(job: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure minimal required fields exist before persisting."""
    payload = dict(job)
    payload["host"] = (payload.get("host") or "").lower()
    payload["case_id"] = (payload.get("case_id") or "").lower()
    tenant = payload.get("tenant_id")
    if tenant:
        payload["tenant_id"] = tenant.lower()
    timeline = payload.get("timeline")
    if isinstance(timeline, list):
        payload["timeline"] = timeline[:10]
    sandbox = payload.get("sandbox")
    if sandbox and isinstance(sandbox, dict):
        payload["sandbox"] = {k: sandbox.get(k) for k in ("status", "verdict", "submitted_at")}
    return payload


def record_memory_job(job: Dict[str, Any]) -> Dict[str, Any]:
    return MEMORY_JOB_STORE.record_job(normalize_job_payload(job))
