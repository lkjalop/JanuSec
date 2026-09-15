from src.reporting.persona_parser import parse_persona_text, validate_parsed_persona


def test_repair_json_like():
    # Simulate an LLM that returns nearly-JSON but with single quotes and trailing commas
    broken = """
    { 'summary': 'Malicious file found', 'actions': [ {'desc':'Fetch artifact','urgency':'urgent'}, ], 'evidence_refs': ['deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'], }
    """
    parsed = parse_persona_text(broken)
    valid, errs = validate_parsed_persona(parsed)
    assert valid, f"Repair failed: {errs} -> {parsed}"
