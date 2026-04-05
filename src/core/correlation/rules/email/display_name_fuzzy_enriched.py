from __future__ import annotations
from typing import Dict, Any
from difflib import SequenceMatcher
from ..registry import register_rule


def fuzzy_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a or '', b or '').ratio()


@register_rule(name='email_display_name_fuzzy_enriched', mitre=['T1598.002'], factors_required=['display_name','user_directory_lookup'], window_seconds=86400, severity='high', confidence_boost=0.45)
def email_display_name_fuzzy_enriched(event: Dict[str, Any]) -> bool:
    display = (event.get('display_name') or '').lower()
    lookup = event.get('user_directory_lookup') or {}
    score = 0.1

    # lookup expected display name for the from_address recipient
    expected = ''
    if lookup and isinstance(lookup, dict):
        expected = (lookup.get('display_name') or '').lower()

    if expected:
        sim = fuzzy_similarity(display, expected)
        # token-level mismatch: first/last match but extra/changed tokens
        try:
            display_tokens = [t for t in display.split() if t]
            expected_tokens = [t for t in expected.split() if t]
            if len(display_tokens) >= 2 and len(expected_tokens) >= 2:
                if display_tokens[0] == expected_tokens[0] and display_tokens[-1] == expected_tokens[-1]:
                    if display_tokens != expected_tokens:
                        score += 0.5
        except Exception:
            pass
        # high mismatch increases score
        if sim < 0.6:
            score += 0.5
        elif sim < 0.85:
            score += 0.25

    try:
        event.setdefault('correlation_emission', {})
        event['correlation_emission'].update({
            'rule': 'email_display_name_fuzzy_enriched',
            'mitre': ['T1598.002'],
            'computed_score': round(min(score, 0.99), 3),
            'evidence': {'display': display, 'expected': expected, 'similarity': round(sim,3) if expected else None},
        })
    except Exception:
        pass

    return score >= 0.55
