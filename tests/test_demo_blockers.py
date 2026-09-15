"""Tests for the three demo-stability blockers.

1. SSE auth — progress streaming uses headers; credentials are not placed in URLs.
2. Mock LLM — LocalDeterministicClient must accept model kwarg and implement generate_batch.
3. Duplicate job — enqueue_job must be idempotent for the same assessment_id.
"""
from __future__ import annotations

import asyncio
import json
import os
import time
import unittest.mock as mock
from pathlib import Path

import pytest

# ── Fix 1: SSE progress uses header authentication ─────────────────────────────

@pytest.mark.anyio
async def test_sse_progress_rejects_query_param_credentials(monkeypatch):
    """A valid API key in a URL must not authenticate the progress route."""
    monkeypatch.setenv("STRICT_API_KEY_ENFORCEMENT", "1")
    monkeypatch.setenv(
        "API_KEYS_JSON",
        json.dumps([{"key": "header-key", "scopes": ["*"], "tenant_id": "default"}]),
    )
    monkeypatch.setenv("PLATFORM_LITE_INIT", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    from fastapi import Header, HTTPException
    from fastapi.testclient import TestClient

    from src.api.app import app
    from src.security.auth import AuthContext, require_api_key

    async def _header_only(x_api_key: str | None = Header(None)) -> AuthContext:
        if x_api_key != "header-key":
            raise HTTPException(status_code=401, detail="unauthorized")
        return AuthContext("test", ["*"], tenant_id="default")

    app.dependency_overrides[require_api_key] = _header_only
    try:
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get(
                "/api/v1/assessments/test-aid-sse/progress",
                params={"token": "header-key", "tenant_id": "default"},
            )
            assert resp.status_code == 401
    finally:
        app.dependency_overrides.pop(require_api_key, None)


@pytest.mark.anyio
async def test_sse_progress_accepts_header_authentication(monkeypatch):
    """Header-capable fetch streaming reaches the tenant ownership check."""
    monkeypatch.setenv("STRICT_API_KEY_ENFORCEMENT", "1")
    monkeypatch.setenv(
        "API_KEYS_JSON",
        json.dumps([{"key": "header-key", "scopes": ["*"], "tenant_id": "default"}]),
    )
    monkeypatch.setenv("PLATFORM_LITE_INIT", "0")
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    from fastapi.testclient import TestClient

    from src.api.app import app

    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get(
            "/api/v1/assessments/test-aid-sse/progress",
            headers={"x-api-key": "header-key", "x-tenant-id": "default"},
        )
        assert resp.status_code != 401, (
            f"Expected header authentication to pass, got {resp.status_code}"
        )


def test_breach_progress_stream_uses_header_capable_fetch():
    source = Path("frontend/static/js/breach.js").read_text(encoding="utf-8")
    start = source.index("function _connectSSE")
    end = source.index("function _schedulePollJson", start)
    progress_client = source[start:end]

    assert "new EventSource" not in progress_client
    assert "token=" not in progress_client
    assert "headers.Accept = 'text/event-stream'" in progress_client
    assert "fetch(url" in progress_client


# ── Fix 2: Mock LLM accepts model kwarg and implements generate_batch ──────────

def test_local_deterministic_generate_accepts_model_kwarg():
    """LocalDeterministicClient.generate must not raise when model= is passed."""
    from src.integrations.llm_client import LocalDeterministicClient
    client = LocalDeterministicClient()
    result = client.generate("hello world", max_tokens=64, model="qwen3:14b")
    assert isinstance(result, dict)
    assert "text" in result
    assert result.get("meta", {}).get("model") == "qwen3:14b"


def test_local_deterministic_generate_batch_returns_same_length():
    """generate_batch must return a list of same length as prompts, in order."""
    from src.integrations.llm_client import LocalDeterministicClient
    client = LocalDeterministicClient()
    prompts = ["prompt A", "prompt B", "prompt C"]
    results = client.generate_batch(prompts, max_tokens=64, model="qwen2.5:14b")
    assert isinstance(results, list)
    assert len(results) == len(prompts)
    for r in results:
        assert isinstance(r, dict)
        assert "text" in r


def test_local_deterministic_generate_batch_is_deterministic():
    """Same prompts must produce same text each time."""
    from src.integrations.llm_client import LocalDeterministicClient
    client = LocalDeterministicClient()
    prompts = ["stable prompt 1", "stable prompt 2"]
    r1 = client.generate_batch(prompts)
    r2 = client.generate_batch(prompts)
    for a, b in zip(r1, r2):
        assert a["text"] == b["text"]


def test_local_deterministic_generate_accepts_unknown_kwargs():
    """generate must silently ignore unknown kwargs — no TypeError."""
    from src.integrations.llm_client import LocalDeterministicClient
    client = LocalDeterministicClient()
    result = client.generate(
        "test",
        max_tokens=32,
        model="test-model",
        temperature=0.7,   # unknown kwarg
        stream=False,      # unknown kwarg
    )
    assert "text" in result


# ── Fix 3: Duplicate job deduplication ────────────────────────────────────────

def test_enqueue_job_is_idempotent():
    """Enqueuing the same assessment_id twice must result in only one queue entry."""
    # Reset module state so test is isolated
    import importlib

    import src.core.ingest.assessment_worker as aw
    importlib.reload(aw)

    run_count = 0

    async def _count_runs(aid, org, fps, *, progress_fn=None):
        nonlocal run_count
        run_count += 1

    with mock.patch.object(aw, "run_assessment_pipeline", side_effect=_count_runs):
        aw.enqueue_job("dup-test-001", "org", [("/fake/path", "file.csv")])
        aw.enqueue_job("dup-test-001", "org", [("/fake/path", "file.csv")])  # duplicate

        async def drain():
            await asyncio.sleep(0)  # let loop tick
            task = asyncio.get_event_loop().create_task(aw._worker_loop())
            await asyncio.sleep(0.05)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        asyncio.get_event_loop().run_until_complete(drain())

    assert run_count <= 1, (
        f"Expected run_assessment_pipeline called at most once, got {run_count}. "
        "Duplicate job was processed."
    )


def test_enqueue_job_allows_different_assessment_ids():
    """Two different assessment_ids must both be enqueued independently."""
    import importlib

    import src.core.ingest.assessment_worker as aw
    importlib.reload(aw)

    aw.enqueue_job("job-aaa", "org", [("/fake/a", "a.csv")])
    aw.enqueue_job("job-bbb", "org", [("/fake/b", "b.csv")])

    queued = set()
    while not aw._INGEST_QUEUE.empty():
        job = aw._INGEST_QUEUE.get_nowait()
        if job:
            queued.add(job["assessment_id"])

    assert "job-aaa" in queued
    assert "job-bbb" in queued


def test_enqueue_job_allows_requeue_after_completion():
    """After a job completes (removed from _ACTIVE_JOB_IDS), same id can be requeued."""
    import importlib

    import src.core.ingest.assessment_worker as aw
    importlib.reload(aw)

    aw.enqueue_job("requeue-001", "org", [("/fake/path", "file.csv")])
    # Simulate job completion by removing from active set
    aw._ACTIVE_JOB_IDS.discard("requeue-001")
    # Drain the first job from queue
    aw._INGEST_QUEUE.get_nowait()

    # Should now be enqueueable again
    aw.enqueue_job("requeue-001", "org", [("/fake/path", "file.csv")])
    assert not aw._INGEST_QUEUE.empty()
