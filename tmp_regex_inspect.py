from src.core.rules.schema import load_rule_from_yaml
from src.core.rules.runner import _match_condition_on_node_dict
r = load_rule_from_yaml('rules/examples/email_bec_chain.yaml')
print('raw value repr:', repr(r.conditions[0].value))
print('type:', type(r.conditions[0].value))
node = {'id':'email:supplier@gmail.com|subject:Invoice payment needed','node_type':'email','from_domain':'supplier@gmail.com','subject':'Invoice payment needed'}
print('match from_domain:', _match_condition_on_node_dict(node, 'from_domain', r.conditions[0].op, r.conditions[0].value))
print('match subject:', _match_condition_on_node_dict(node, 'subject', r.conditions[1].op, r.conditions[1].value))
