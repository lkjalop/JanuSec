from __future__ import annotations

import pytest

import src.core.workload_budgets as budgets


def test_embedding_budget_fails_bounded_wait_instead_of_starving(monkeypatch):
    monkeypatch.setattr(budgets, "_EMBEDDING_SEMAPHORE", __import__("threading").BoundedSemaphore(1))
    with budgets.embedding_slot(timeout_seconds=0):
        with pytest.raises(TimeoutError, match="embedding_concurrency_budget_exhausted"):
            with budgets.embedding_slot(timeout_seconds=0):
                pass
