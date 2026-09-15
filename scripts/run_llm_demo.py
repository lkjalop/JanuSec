import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.api.llm_tier1 import summarize_tier1 as _s1
from src.api.llm_tier1 import build_tier1_prompt as _bp
from src.core.correlation.tier1_summarizer import summarize_tier1
from src.core.correlation.llm_prompt import build_tier1_prompt


def demo():
    event = {
        'correlation_emission': {'rule':'email_bec_impersonation_enriched','computed_score':0.82,'mitre':['T1598.002'],'evidence':{'from':'ceo@notcorp.com','display':'CEO','reply_to':'att@malicious.com'}},
        'factors':[{'name':'display_mismatch','score':0.9},{'name':'replyto_mismatch','score':0.8}],
    }
    # mimic pydantic model behavior by wrapping in dict
    # Directly run the same logic as the endpoint
    summary = summarize_tier1(event)
    prompt = build_tier1_prompt(summary, event)
    score = float(summary.get('score') or 0.0)
    if score >= 0.8:
        action = 'ESCALATE'
        rationale = 'High confidence BEC-style impersonation; reply-to mismatch and strong factors.'
        next_steps = ['Block sender domain at tenant gateway', 'Open incident and assign to analyst']
    elif score >= 0.5:
        action = 'INVESTIGATE'
        rationale = 'Moderate confidence; requires human review of attachments and headers.'
        next_steps = ['Verify DKIM/SPF/DMARC results', 'Check user directory display name match']
    else:
        action = 'NO_ACTION'
        rationale = 'Low confidence; likely benign or whitelisted.'
        next_steps = ['Record and monitor']
    print({'action': action, 'rationale': rationale, 'next_steps': next_steps, 'prompt': prompt})

if __name__ == '__main__':
    demo()
