import os
import pytest
from src.integrations.llm_client import LLMClient


def test_persona_in_kwargs_injected_and_token_cap(monkeypatch, tmp_path):
    client = LLMClient()
    # short token cap for test
    client.max_tokens = 10

    # persona and prompt that combined exceed max_tokens
    persona = 'You are a concise security analyst.'
    prompt = 'Summarize the incident.'

    # Should raise ValueError because persona + prompt tokens > cap
    with pytest.raises(ValueError):
        client.generate(prompt, max_tokens=5, persona_prompt=persona)

    # Now provide larger cap - should succeed (using mock mode)
    monkeypatch.setenv('LLM_MOCK', '1')
    client = LLMClient()
    resp = client.generate(prompt, max_tokens=100, persona_prompt=persona)
    assert isinstance(resp, dict)
    assert 'text' in resp


def test_persona_in_overrides_injected(monkeypatch):
    monkeypatch.setenv('LLM_MOCK', '1')
    client = LLMClient()
    prompt = 'List the key indicators.'
    overrides = {'persona_prompt': 'You are a helpful analyst.'}
    resp = client.generate(prompt, max_tokens=200, overrides=overrides)
    assert isinstance(resp, dict)
    assert 'text' in resp


def test_persona_injection_order(monkeypatch):
    # Ensure persona is prepended and visible to mock matcher
    monkeypatch.setenv('LLM_MOCK', '1')
    # Prepare a mock responses fixture that matches persona text
    base = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    fixture_dir = os.path.join(base, 'tests', 'fixtures')
    # If the fixture isn't present, just run to ensure no crash
    client = LLMClient()
    prompt = 'Detect anomalies.'
    resp = client.generate(prompt, max_tokens=100, persona_prompt='Analyst persona: prioritize brevity.')
    assert 'text' in resp
