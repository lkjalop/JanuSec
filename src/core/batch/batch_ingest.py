"""Batch Ingestion Scaffold

Lightweight placeholder for registering and running historical / offline ingestion jobs.
This is intentionally minimal—full implementation (parquet conversion, pointer walking,
embedding, etc.) deferred until activation.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class BatchJob:
    job_id: str
    dataset_ref: str
    source_type: str  # upload|s3|fs
    window_start: str | None
    window_end: str | None
    status: str = 'registered'  # registered|running|complete|failed|aborted
    created_ts: float = field(default_factory=time.time)
    updated_ts: float = field(default_factory=time.time)
    progress_segments: int = 0
    total_segments: int = 0
    errors: list[str] = field(default_factory=list)
    report: dict[str, object] = field(default_factory=dict)

class BatchIngestManager:
    def __init__(self):
        self._jobs: dict[str, BatchJob] = {}
        self._lock = threading.Lock()

    def register(self, job_id: str, dataset_ref: str, source_type: str, window_start: str | None, window_end: str | None) -> BatchJob:
        with self._lock:
            if job_id in self._jobs:
                raise ValueError('job_exists')
            job = BatchJob(job_id=job_id, dataset_ref=dataset_ref, source_type=source_type, window_start=window_start, window_end=window_end)
            self._jobs[job_id] = job
            return job

    def start(self, job_id: str):
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                raise ValueError('not_found')
            if job.status not in ('registered','failed'):
                raise ValueError('invalid_state')
            job.status = 'running'; job.updated_ts = time.time()
        # Placeholder thread that marks complete quickly
        t = threading.Thread(target=self._run_placeholder, args=(job_id,), daemon=True)
        t.start()

    def _run_placeholder(self, job_id: str):
        time.sleep(0.25)
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.status != 'running':
                return
            job.progress_segments = 1
            job.total_segments = 1
            job.status = 'complete'
            job.report = {
                'note': 'Placeholder batch job completed (no-op)',
                'dataset_ref': job.dataset_ref,
                'segments': 1,
                'events_processed': 0
            }
            job.updated_ts = time.time()

    def status(self, job_id: str) -> BatchJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def report(self, job_id: str) -> dict[str, object] | None:
        job = self.status(job_id)
        return None if not job else job.report

_singleton: BatchIngestManager | None = None

def get_batch_manager() -> BatchIngestManager:
    global _singleton
    if _singleton is None:
        _singleton = BatchIngestManager()
    return _singleton
