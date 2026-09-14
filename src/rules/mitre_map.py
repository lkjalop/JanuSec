from __future__ import annotations
MITRE_MAP = {
    'T1059': {'name':'Command and Scripting Interpreter','tactic':'Execution'},
    'T1105': {'name':'Ingress Tool Transfer','tactic':'Command and Control'},
    'T1057': {'name':'Process Discovery','tactic':'Discovery'},
}

def summarize_mitre_for_rules(rules: list[dict]) -> dict:
    summary = {}
    for r in rules:
        for t in r.get('mitre', []) or []:
            if t not in summary:
                summary[t] = MITRE_MAP.get(t, {'name':'unknown','tactic':'unknown'})
    return summary
