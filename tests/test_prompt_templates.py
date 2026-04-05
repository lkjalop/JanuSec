from src.reporting.prompt_templates import build_persona_prompt, PERSONA_TEMPLATES


def test_build_persona_prompt_basic():
    p = build_persona_prompt('soc_analyst', context={'id': 1}, base_summary='base')
    assert isinstance(p, dict)
    assert 'messages' in p and isinstance(p['messages'], list)
    assert p.get('persona') in {'soc_analyst', 'executive', 'compliance'}
