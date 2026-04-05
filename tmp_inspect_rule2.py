from src.core.rules.schema import load_rule_from_yaml
r = load_rule_from_yaml('rules/examples/email_bec_chain.yaml')
print('meta.id:', getattr(r.meta,'id',None))
print('rule.conditions:', [(c.field,c.op,c.value) for c in r.conditions])
print('rule.joins:', r.joins)
