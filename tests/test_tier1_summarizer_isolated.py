from src.core.correlation.tier1_summarizer import summarize_tier1


def test_summarize_basic():
    event = {
        'correlation_emission': {
            'rule': 'email_bec_impersonation_enriched',
            'computed_score': 0.75,
            'mitre': ['T1598.002'],
            'evidence': {'from': 'attacker@example.com', 'display': 'John Doe', 'reply_to': 'attacker@malicious.com'},
        },
        'factors': [
            {'name': 'display_mismatch', 'score': 0.9},
            {'name': 'replyto_mismatch', 'score': 0.8},
        ],
    }

    s = summarize_tier1(event)

    assert s['title'] == 'email_bec_impersonation_enriched'
    assert abs(s['score'] - 0.75) < 0.001
    assert 'T1598.002' in s['mitre']
    # deterministic ordering of reason keys
    assert any('display=' in r for r in s['reason'])
    assert s['top_factors'][0]['name'] == 'display_mismatch'
