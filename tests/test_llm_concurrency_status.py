from src.integrations.llm_client import get_client_status
from src.integrations.llm_concurrency import LLMConcurrencyLimiter


def test_llm_concurrency_limiter_reports_state(monkeypatch):
    monkeypatch.setenv("LLM_MAX_CONCURRENT", "2")
    limiter = LLMConcurrencyLimiter()

    with limiter.acquire(label="test") as gate:
        assert gate["limit"] == 2
        snapshot = limiter.snapshot()
        assert snapshot["limit"] == 2
        assert snapshot["active"] == 1

    assert limiter.snapshot()["active"] == 0


def test_client_status_exposes_concurrency():
    status = get_client_status()

    assert "concurrency" in status
    assert "limit" in status["concurrency"]
