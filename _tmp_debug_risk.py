from core.risk_score import compose_risk_score, _default_weight_for_factor
dec={'factors':['net:beacon_periodic','dns:tunnel_suspected'],'confidence':0.5}
print('Input factors:', dec['factors'])
print('Default net weight:', _default_weight_for_factor('net:beacon_periodic'))
print('Result:', compose_risk_score(dec))
