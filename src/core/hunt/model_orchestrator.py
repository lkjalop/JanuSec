"""Model Orchestrator Policy

Defines escalation & degradation logic across model tiers.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Optional

TIERS = [0,1,2,3,4]

@dataclass
class ModelDecision:
    tier: int
    model_id: str
    reason: str

def select_model(severity: float, confidence: float, budget_remaining_ratio: float, availability: Dict[int,bool]) -> ModelDecision:
    # Base desired tier from severity
    if severity >= 0.85: desired = 3
    elif severity >= 0.6: desired = 2
    elif severity >= 0.3: desired = 1
    else: desired = 0
    # Escalate on low confidence given headroom
    if confidence < 0.4 and budget_remaining_ratio > 0.25:
        desired = min(desired+1, 3)
    # Degrade if low budget
    if budget_remaining_ratio < 0.1:
        desired = max(0, desired-1)
    # Availability pass
    chosen = desired
    while chosen >=0 and not availability.get(chosen, False):
        chosen -= 1
    if chosen < 0:
        return ModelDecision(tier=0, model_id='heuristic-only', reason='no_tier_available')
    model_map = {
        0: 'heuristic-only',
        1: 'all-MiniLM-L6-v2',
        2: 'mistral-7b',
        3: 'mixtral-8x7b',
        4: 'gpt-4o'
    }
    reason_parts = [f'severity={severity:.2f}', f'confidence={confidence:.2f}', f'budget={budget_remaining_ratio:.2f}', f'desired={desired}', f'chosen={chosen}']
    return ModelDecision(tier=chosen, model_id=model_map.get(chosen,'heuristic-only'), reason=';'.join(reason_parts))
