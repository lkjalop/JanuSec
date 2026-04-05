from src.reporting.persona_parser import parse_persona_text


def test_parse_json_persona_text():
    text = '{"summary": "This is a summary.", "actions": [{"desc":"Isolate host","urgency":"immediate"}], "evidence_refs": ["evt_123"]}'
    out = parse_persona_text(text)
    assert out['summary'].startswith('This is a summary')
    assert isinstance(out['actions'], list) and out['actions'][0]['urgency'] == 'immediate'
    assert out['evidence_refs'] == ['evt_123']


def test_parse_plain_text_bullets():
    text = """
    This incident shows anomalous process creation.
    - Isolate the host immediately.
    - Collect memory dump.
    Evidence: evt_abc123
    """
    out = parse_persona_text(text)
    assert 'anomalous process' in out['summary'].lower()
    assert any('isolate' in a['desc'].lower() for a in out['actions'])
    assert 'evt_abc123' in out['evidence_refs']
