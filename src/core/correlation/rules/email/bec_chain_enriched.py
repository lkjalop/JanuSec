from __future__ import annotations
from typing import Dict, Any
from ..registry import register_rule


@register_rule(name='bec_chain_enriched', mitre=['T1598','T1204'], factors_required=['thread_context','attachments','indicators'], window_seconds=86400, severity='high', confidence_boost=0.45)
def bec_chain_enriched(event: Dict[str, Any]) -> bool:
	tc = event.get('thread_context') or {}
	atts = event.get('attachments') or []
	inds = event.get('indicators') or {}
	score = 0.2

	try:
		participants = tc.get('participants') or []
		recent = tc.get('recent_actions') or []
		# urgency language and reply-to mismatch helps
		if bool(inds.get('urgency_language')):
			score += 0.2
		if bool(inds.get('reply_to_mismatch')):
			score += 0.2
		# macro or payment instruction attachments increase score
		if any((a.get('filename') or '').lower().endswith(('.docm','.xlsm')) for a in atts):
			score += 0.2
		if any(('payment' in (a.get('filename','').lower())) for a in atts):
			score += 0.1
		# chain context: executive + finance participants and wire/invoice actions
		if any('ceo' in (p or '').lower() for p in participants) and any('finance' in (p or '').lower() for p in participants):
			if any(('wire' in x.lower() or 'invoice' in x.lower()) for x in recent):
				score += 0.2
	except Exception:
		pass

	try:
		event.setdefault('correlation_emission', {})
		event['correlation_emission'].update({
			'rule': 'bec_chain_enriched',
			'mitre': ['T1598','T1204'],
			'computed_score': round(min(score, 0.99), 3),
			'evidence': {
				'participants': tc.get('participants'),
				'recent_actions': tc.get('recent_actions'),
				'attachments': [a.get('filename') for a in atts],
				'indicators': inds,
			},
		})
	except Exception:
		pass

	return score >= 0.6
