import pytest
from src.reporting.persona_parser import parse_persona_text, validate_parsed_persona

CASES = [
    (
        "{""summary"": ""Block suspicious IP"", ""actions"": [{""desc"": ""Block 1.2.3.4 at firewall""},], ""evidence_refs"": [""evt_abc""]}",
        True,
    ),
    (
        "{'summary': 'Isolate host', 'actions': [{'desc': 'EDR isolate host-01',}], 'evidence_refs': ['evt_123'],}",
        True,
    ),
    (
        "Recommendation: {'summary': 'Containment required', 'recommended_actions': ['Disable user alice','Block 9.9.9.9',],}",
        True,
    ),
    (
        "Summary: Something suspicious.\n- Block 4.3.2.1 now\n- Investigate parent process",
        True,
    ),
    (
        "{""summary"": "", ""actions"": [], }",  # empty/invalid
        False,
    ),
]

@pytest.mark.parametrize("text,expected_valid", CASES)
def test_persona_parser_adversarial_cases(text, expected_valid):
    # fenced JSON with backticks
    (
        """
        ```json
        {"summary":"Contain suspected beacon","actions":[{"desc":"Block 8.8.8.8"},{"desc":"Quarantine file"}],"evidence_refs":["evt_999"]}
        ```
        """,
        True,
    ),
    # unquoted keys, array with quotes inside strings
    (
        '{summary: "Investigate", actions: ["Check \"svc-host\" startup", "Capture memory"], evidence_refs: []}',
        True,
    ),
    # nested recommended_actions object
    (
        '{"summary":"Escalate to IR","recommended_actions":["Disable user bob","Isolate host-02"],"meta":{"tier":2}}',
        True,
    ),
    parsed = parse_persona_text(text)
    valid, errs = validate_parsed_persona(parsed)
    if expected_valid:
        assert valid, f"should be valid, got errs={errs}, parsed={parsed}"
        # confidence should be in [0,1]
        assert 0.0 <= float(parsed.get('confidence') or 0.0) <= 1.0
    else:
        assert not valid
