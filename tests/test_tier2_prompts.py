import pytest

from src.ai.tier2_prompts import build_tier2_prompt_context, SECTIONS


def test_build_tier2_prompt_context_minimal():
    payload = {'assessment_id': 'a1', 'rows': [{'row_index': 0, 'factors': ['f1'], 'triage_score': 0.8}], 'org': 'demo'}
    ctx = build_tier2_prompt_context(payload)
    assert 'sections' in ctx
    assert ctx['sections'] == SECTIONS
    assert 'context' in ctx
    c = ctx['context']
    assert c['assessment_id'] == 'a1'
    assert c['rows_count'] == 1
    assert isinstance(c['sample_evidence'], list)
    ev = c['sample_evidence'][0]
    assert ev['row_index'] == 0
    assert isinstance(ev['top_factors'], list)


def test_build_tier2_prompt_context_empty_rows():
    payload = {'assessment_id': 'a2', 'rows': [], 'org': 'demo'}
    ctx = build_tier2_prompt_context(payload)
    assert ctx['context']['rows_count'] == 0
    assert ctx['context']['sample_evidence'] == []
