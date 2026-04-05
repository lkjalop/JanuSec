import pytest

from types import SimpleNamespace


class _DeterministicMockClient:
    def __init__(self):
        self.calls = []

    async def generate(self, prompt, max_tokens=256, tenant_id=None, **kwargs):
        self.calls.append((prompt, max_tokens, tenant_id))
        return {
            "id": "mock-1",
            "object": "text_completion",
            "choices": [{"text": "This is a deterministic mock summary.", "index": 0}],
            "usage": {"total_tokens": 10},
        }

    def tier1_summarize(self, ctx):
        return "mock-tier1"

    def tier2_analyze(self, ctx):
        return "mock-tier2"


@pytest.fixture(autouse=True)
def llm_default_client_mock(monkeypatch):
    """Replace the runtime DEFAULT_CLIENT with a deterministic mock.

    This fixture runs automatically to prevent tests from calling an external
    Ollama instance while running in CI or locally.
    """
    try:
        from src.integrations import llm_client

        mock_client = _DeterministicMockClient()
        monkeypatch.setattr(llm_client, "DEFAULT_CLIENT", mock_client)
        yield mock_client
    except Exception:
        # If the module isn't importable for some reason, still yield a noop
        yield SimpleNamespace()
