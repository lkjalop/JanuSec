from src.core.rules.schema import load_rule_from_yaml
r = load_rule_from_yaml('rules/examples/email_bec_chain.yaml')
print('conditions:', [(c.field,c.op,c.value) for c in r.conditions])
print('joins:', r.joins)
print('condition_groups[0].joins present?:', bool(r.condition_groups and getattr(r.condition_groups[0],'joins', None)))
