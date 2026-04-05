from src.core.rules.schema import load_rule_from_yaml
from src.core.rules.runner import _match_condition_on_node_dict
r = load_rule_from_yaml('rules/examples/email_bec_chain.yaml')
val = r.conditions[0].value
print('repr val:', repr(val))
print('backslash count:', val.count('\\'))
node = {'id':'email:supplier@gmail.com|subject:Invoice payment needed','node_type':'email','from_domain':'supplier@gmail.com','subject':'Invoice payment needed'}
print('match original:', _match_condition_on_node_dict(node,'from_domain','regex',val))
# try unescaping backslashes
un = val.replace('\\\\','\\')
print('repr unescaped:', repr(un))
print('backslash count unescaped:', un.count('\\'))
print('match unescaped:', _match_condition_on_node_dict(node,'from_domain','regex',un))
PY
