from src.core.hunt.evidence_envelope import EvidenceEnvelope
from src.core.hunt.lanes.email_bec import build as build_email_bec


def test_email_bec_lane_display_name_spoof():
    env = EvidenceEnvelope({'id': 'evt-1'})
    # Provide headers and body attributes expected by lane
    env.headers = {'From': 'CEO John Smith <attacker@evil.com>', 'Subject': 'Important'}
    env.body = 'Please transfer the funds immediately to the account listed below.'
    lane = build_email_bec()
    lane(env)
    factors = env.all_factors
    assert 'email:display_name_spoof' in factors
    assert 'email:financial_keywords' in factors or 'email:urgency_keywords' in factors


def test_email_bec_lane_reply_to_spoofed_thread():
    env = EvidenceEnvelope({'id': 'evt-2'})
    env.headers = {'From': 'alice@external.com', 'Subject': 'Re: Invoice', 'In-Reply-To': None, 'Reply-To': 'payments@evil.com'}
    env.body = 'See attached invoice for payment.'
    lane = build_email_bec()
    lane(env)
    factors = env.all_factors
    assert 'email:reply_to_mismatch' in factors or 'email:sender_spoofed_thread' in factors
