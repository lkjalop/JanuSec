from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any, Dict

from src.integrations.sandbox.cuckoo_provider import CuckooProvider
from src.integrations.sandbox.generic_provider import GenericSandboxProvider
from src.artifact.memory_repository import record_memory_job


SUBMISSIONS_PATH = os.getenv("SANDBOX_SUBMISSIONS_PATH", "data/memory_jobs/sandbox_submissions.jsonl")
RESULTS_PATH = os.getenv("SANDBOX_RESULTS_PATH", "data/memory_jobs/sandbox_results.jsonl")
MAX_SUBMIT_SIZE = int(os.getenv("SANDBOX_MAX_SUBMIT_BYTES", str(50 * 1024 * 1024)))  # 50MB default


def _persist_submission(record: Dict[str, Any]) -> None:
    path = os.getenv("SANDBOX_SUBMISSIONS_PATH", SUBMISSIONS_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _persist_result(record: Dict[str, Any]) -> None:
    path = os.getenv("SANDBOX_RESULTS_PATH", RESULTS_PATH)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


def _scrub_meta(meta: Dict[str, Any]) -> Dict[str, Any]:
    # Remove sensitive tenant tokens/credentials before outbound submission
    m = dict(meta)
    for k in ("api_key", "password", "secret", "token"):
        if k in m:
            m.pop(k, None)
    return m


async def submit_artifact(artifact_id: str, file_bytes: bytes | None, filename: str | None, url: str | None, provider_name: str = "cuckoo", meta: Dict[str, Any] | None = None) -> str:
    """Submit an artifact to the selected sandbox provider and persist the task id.

    Returns the task_id (or simulated id) and schedules background polling to fetch results.
    """
    meta = meta or {}
    provider_name = provider_name.lower()

    # Size guard
    if file_bytes is not None and len(file_bytes) > MAX_SUBMIT_SIZE:
        raise ValueError(f"artifact too large for sandbox submission (> {MAX_SUBMIT_SIZE} bytes)")

    # Scrub meta
    scrubbed = _scrub_meta(meta)

    # Choose provider
    if provider_name == "cuckoo":
        provider = CuckooProvider()
    elif provider_name == "generic":
        provider = GenericSandboxProvider(name=meta.get('provider_cfg_name') or 'cuckoo')
    else:
        # Try to use a config-driven provider with the given name
        provider = GenericSandboxProvider(name=provider_name)

    task_id = await provider.submit(file_bytes, filename, url)

    record = {
        "artifact_id": artifact_id,
        "provider": provider_name,
        "task_id": task_id,
        "submitted_at": time.time(),
        "meta": scrubbed,
    }
    _persist_submission(record)

    # Persist submission into canonical memory job store
    job_payload = {
        'job_id': record['task_id'],
        'artifact_id': artifact_id,
        'tenant_id': scrubbed.get('tenant_id'),
        'host': scrubbed.get('host'),
        'sandbox': {'status': 'submitted', 'submitted_at': record['submitted_at'], 'task_id': record['task_id']},
        'meta': scrubbed,
    }
    record_memory_job(job_payload)

    # Schedule background poller to fetch results and persist them
    async def _poll_and_persist(tid: str):
        try:
            res = await provider.result(tid)
            result_record = {
                'artifact_id': artifact_id,
                'provider': provider_name,
                'task_id': tid,
                'submitted_at': record['submitted_at'],
                'result': res,
            }
            _persist_result(result_record)
            out = {
                'job_id': tid,
                'artifact_id': artifact_id,
                'sandbox': {'status': 'completed' if res else 'pending', 'verdict': (res or {}).get('verdict') if isinstance(res, dict) else None, 'submitted_at': record['submitted_at']},
                'result': res,
            }
            record_memory_job(out)
        finally:
            # ensure provider client close
            try:
                await provider.close()
            except Exception:
                pass

    # fire-and-forget: schedule the poller on the running loop if present,
    # otherwise run it in a background thread so callers (tests/CLI) don't hang.
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_poll_and_persist(task_id))
    except RuntimeError:
        # No running loop: launch a background thread that runs its own asyncio loop
        import threading

        def _bg_runner(tid: str) -> None:
            try:
                asyncio.run(_poll_and_persist(tid))
            except Exception:
                pass

        threading.Thread(target=_bg_runner, args=(task_id,), daemon=True).start()

    return task_id
