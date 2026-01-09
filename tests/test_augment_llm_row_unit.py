import time

from src.api.deep_analyze_endpoints import _augment_llm_row


def test_augment_llm_row_basic():
    """Unit test: calling _augment_llm_row should attach cost, tokens, and persona placeholders without error."""
    sample = {'row_index': 0, 'process': 'cmd.exe', 'host': 'host1'}
    assessment = {'assessment_id': 'a1', 'org': 'org1'}
    before = dict(sample)
    out = _augment_llm_row(sample, assessment)
    # Ensure some expected keys were added
    assert out.get('_llm_processed') is True
    assert isinstance(out.get('_llm_timestamp'), int)
    assert isinstance(out.get('_llm_tokens'), dict)
    assert isinstance(out.get('_llm_cost'), (int, float))
    assert isinstance(out.get('persona_reports'), dict)
    # persona reports should at least contain keys (soc,ciso,compliance)
    for k in ('soc','ciso','compliance'):
        assert k in out.get('persona_reports')
