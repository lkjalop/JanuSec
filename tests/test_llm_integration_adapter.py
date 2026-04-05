import os
from src.analysis.auto_llm import LLMAssessmentClient


def test_llm_assessment_client_returns_shape(monkeypatch):
    # Ensure mock mode is active so tests are deterministic
    monkeypatch.setenv('LLM_MOCK', '1')
    client = LLMAssessmentClient()
    row = {'process_name': 'svc.exe', 'file_hash': 'abc123', 'host': 'host1', 'user': 'alice'}
    out = client.summarize_row(row, {'org': 'test_org'})
    assert isinstance(out, dict)
    assert 'text' in out
    assert 'model' in out
    assert 'meta' in out
