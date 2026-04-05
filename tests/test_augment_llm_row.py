from src.api.deep_analyze_endpoints import _augment_llm_row


def test_augment_parses_persona_text():
    row = {'row_index': 1, 'llm_summary': 'base', 'persona_reports': {'soc': {'text': 'Summary line.\n- Isolate host now.\nEvidence: evt_1'}}}
    assess = {'assessment_id': 'a1'}
    out = _augment_llm_row(row, assess)
    pr = out.get('persona_reports', {})
    assert 'soc' in pr
    parsed = pr['soc'].get('parsed')
    assert parsed and parsed.get('summary')
    assert parsed.get('evidence_refs')
