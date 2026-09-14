import pytest


def test_summarize_row_forwards_overrides(monkeypatch):
    calls = {}

    class DummyClient:
        def generate(self, prompt, **kwargs):
            calls['args'] = {'prompt': prompt, **kwargs}
            return {'text': 'ok', 'model': kwargs.get('model') or 'mymodel', 'meta': {}}

    # Patch the DEFAULT_CLIENT used by LLMAssessmentClient
    # Use dotted target to ensure correct module attribute is replaced
    monkeypatch.setattr('src.integrations.llm_client.DEFAULT_CLIENT', DummyClient(), raising=False)

    from src.analysis.auto_llm import LLMAssessmentClient

    client = LLMAssessmentClient()
    row = {'row_index': 1, 'process_name': 'proc'}
    context = {
        'overrides': {'ollama_host': 'http://localhost:11434', 'ollama_model': 'ggml-model'},
        'model': 'test-model',
    }

    out = client.summarize_row(row, context)

    assert 'args' in calls, 'generate was not called on the DEFAULT_CLIENT'
    assert 'overrides' in calls['args'] and calls['args']['overrides'] == context['overrides']
    assert calls['args'].get('model') == 'test-model'
    assert isinstance(out, dict)
