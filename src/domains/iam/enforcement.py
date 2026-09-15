from typing import Dict, Any, Optional
import time


class EnforcementController:
    def __init__(self):
        # simple AB toggles: rule_name -> variant ('auto'|'suggest')
        self.toggles: Dict[str, str] = {}
        # feedback store: list of {rule,action,actor,ts,feedback}
        self.feedback: list[Dict[str, Any]] = []

    def set_toggle(self, rule: str, variant: str = 'suggest'):
        if variant not in ('auto', 'suggest'):
            raise ValueError('variant must be auto or suggest')
        self.toggles[rule] = variant

    def get_toggle(self, rule: str) -> str:
        return self.toggles.get(rule, 'suggest')

    def record_feedback(self, rule: str, action: str, actor: str, feedback: str):
        self.feedback.append({'rule': rule, 'action': action, 'actor': actor, 'feedback': feedback, 'ts': time.time()})

    def recent_feedback(self, rule: str, limit: int = 20):
        return [f for f in self.feedback if f.get('rule') == rule][-limit:]
