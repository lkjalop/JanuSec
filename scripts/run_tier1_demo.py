import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.core.correlation.tier1_summarizer import summarize_tier1
from src.core.correlation.llm_prompt import build_tier1_prompt

# craft a sample event
event = {
    'correlation_emission': {
        'rule': 'email_bec_impersonation_enriched',
        'computed_score': 0.82,
        'mitre': ['T1598.002'],
        'evidence': {'from': 'ceo@notcorp.com', 'display': 'CEO John Doe', 'reply_to': 'att@malicious.com'},
    },
    'factors': [
        {'name': 'display_mismatch', 'score': 0.9},
        {'name': 'replyto_mismatch', 'score': 0.8},
    ],
}

summary = summarize_tier1(event)
print('SUMMARY:')
print(summary)
print('\nPROMPT:')
print(build_tier1_prompt(summary, event))
