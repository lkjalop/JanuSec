import os
import pytest
from src.integrations.llm_client import LLMClient


def test_default_client_persona_in_kwargs(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '1')
    client = LLMClient()
    resp = client.generate('Short prompt', max_tokens=200, persona_prompt='Persona text')
    assert isinstance(resp, dict)
    assert 'text' in resp


def test_default_client_persona_in_overrides(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '1')
    client = LLMClient()
    overrides = {'persona_prompt': 'Override persona'}
    resp = client.generate('Another prompt', max_tokens=200, overrides=overrides)
    assert isinstance(resp, dict)
    assert 'text' in resp


def test_default_client_provider_overrides(monkeypatch):
    # exercise override path (ollama override path uses overrides dict)
    monkeypatch.setenv('LLM_MOCK', '1')
    client = LLMClient()
    overrides = {'ollama_host': 'http://127.0.0.1:11434', 'persona_prompt': 'ProvOverride persona'}
    resp = client.generate('Provider override prompt', max_tokens=200, overrides=overrides)
    assert isinstance(resp, dict)
    assert 'text' in resp


def test_ollama_generate_uses_per_request_model(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '0')
    client = LLMClient()
    client.mock = False
    client.provider = 'ollama'
    client.ollama_enabled = True
    client.ollama_model = 'configured-default'
    client.interactive_model = None

    seen = {}

    def fake_ollama(prompt, max_tokens, model_override=None):
        seen['model_override'] = model_override
        return {'text': 'ok', 'model': model_override, 'meta': {'provider': 'ollama'}}

    monkeypatch.setattr(client, '_ollama_generate', fake_ollama)
    out = client.generate('hello', 8, model='qwen3:14b')

    assert out['model'] == 'qwen3:14b'
    assert seen['model_override'] == 'qwen3:14b'
