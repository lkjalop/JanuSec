from __future__ import annotations

import pytest

from src.core.async_model_runs import AsyncModelRunStore


def test_model_job_receipts_are_append_only_and_hash_chained(tmp_path):
    store = AsyncModelRunStore(tmp_path)
    queued = store.create(
        tenant_id="tenant-a", assessment_id="assessment-a",
        request={"provider": "ollama", "model": "qwen"}, hard_budget_seconds=30,
    )
    running = store.transition(
        tenant_id="tenant-a", assessment_id="assessment-a", job_id=queued["job_id"],
        status="running", details={"started_at": 1},
    )
    completed = store.transition(
        tenant_id="tenant-a", assessment_id="assessment-a", job_id=queued["job_id"],
        status="completed", details={"run_id": "run-1"},
    )
    assert [item["status"] for item in completed["partial_run_receipts"]] == ["queued", "running", "completed"]
    assert running["receipt_hash"] == completed["partial_run_receipts"][-1]["previous_receipt_hash"]
    with pytest.raises(ValueError, match="already_terminal"):
        store.transition(
            tenant_id="tenant-a", assessment_id="assessment-a", job_id=queued["job_id"],
            status="failed",
        )


def test_model_job_rejects_skipped_state(tmp_path):
    store = AsyncModelRunStore(tmp_path)
    queued = store.create(
        tenant_id="tenant-a", assessment_id="assessment-a", request={}, hard_budget_seconds=5,
    )
    with pytest.raises(ValueError, match="invalid_model_job_transition"):
        store.transition(
            tenant_id="tenant-a", assessment_id="assessment-a", job_id=queued["job_id"],
            status="correcting",
        )
