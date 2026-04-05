from src.core.rules.runner import _match_condition_on_node_dict
node = {'id':'email:supplier@gmail.com|subject:Invoice payment needed','node_type':'email','from_domain':'supplier@gmail.com','subject':'Invoice payment needed'}
print(_match_condition_on_node_dict(node,'from_domain','regex','(gmail|yahoo|hotmail)\\.com$'))
print(_match_condition_on_node_dict(node,'subject','regex','(?i)(invoice|payment|wire)'))
