import time
from src.analysis.auto_llm import (
    LLMAssessmentClient,
    build_llm_prompt,
    should_include_missing_logs,
)


def test_summarize_row_fallback_line_counts():
    client = LLMAssessmentClient()
    # Force fallback path (no external LLM client) for deterministic behavior
    try:
        client._client = None
    except Exception:
        pass
    row = {'process_name': 'cmd.exe', 'factors': ['no_network_logs', 'suspicious_file'], 'host': 'host1', 'user': 'bob'}
    # Ensure deterministic fallback when no LLM available
    out = client.summarize_row(row, context={})
    assert isinstance(out, dict)
    assert 'text' in out
    text = out['text']
    lines = [ln for ln in text.splitlines() if ln.strip()]
    assert 30 <= len(lines) <= 45


def test_semantic_truncate_respects_max_chars():
    client = LLMAssessmentClient()
    # Build a long text by calling summarize_row and forcing max_chars small
    row = {'process_name': 'evil', 'factors': ['a','b','c'], 'host': 'h', 'user': 'u'}
    out = client.summarize_row(row, context={'max_chars': 200})
    assert isinstance(out, dict)
    text = out['text']
    assert len(text) <= 200


def test_should_include_missing_logs_logic():
    # correlation above threshold
    row = {'llm_meta': {'confidence': 0.95}, 'factors': []}
    ctx = {'correlation': {'score': 0.6}}
    assert should_include_missing_logs(row, ctx) is True

    # low confidence
    row = {'llm_meta': {'confidence': 0.5}, 'factors': []}
    ctx = {}
    assert should_include_missing_logs(row, ctx) is True

    # telemetry gaps
    row = {'factors': ['no_parent_process']}
    ctx = {}
    assert should_include_missing_logs(row, ctx) is True

    # negative case
    row = {'llm_meta': {'confidence': 0.99}, 'factors': []}
    ctx = {'correlation': {'score': 0.1}}
    assert should_include_missing_logs(row, ctx) is False


def test_build_llm_prompt_contains_sections_and_context():
    row = {'process_name': 'proc', 'factors': ['x']}
    ctx = {
        'pipeline_context': {
            'dread': {'score': 7},
            'mitre_tags': ['T1003'],
            'correlation': {'score': 0.9},
            'attack_patterns': ['c2'],
        }
    }
    prompt = build_llm_prompt(row, ctx)
    for section in ("WHAT IS IT?", "EXPLOITABILITY", "WHAT TO DO?", "CONCISE PLAYBOOK"):
        assert section in prompt
    assert "PIPELINE CONTEXT" in prompt
    assert '"dread"' in prompt
    assert '"T1003"' in prompt


def test_build_llm_prompt_missing_logs_included_when_flagged():
    row = {'process_name': 'proc', 'factors': ['no_network_logs']}
    ctx = {'pipeline_context': {'correlation': {'score': 0.9}}}
    prompt = build_llm_prompt(row, ctx)
    assert "MISSING LOGS" in prompt
