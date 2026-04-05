from src.api.alerts_endpoints import append_alert, ALERT_RING, ALERT_RING_LOCK, get_canonical_alert_ring
with open('tmp_append_test_out.txt','w',encoding='utf-8') as f:
	f.write(f'before len {len(ALERT_RING)} id {id(ALERT_RING)}\n')
	append_alert({'id':'direct-1','ts': 1234567890, 'tenant_id':'default'})
	f.write(f'after len {len(ALERT_RING)} id {id(ALERT_RING)}\n')
	cr,cl,cm = get_canonical_alert_ring()
	f.write(f'canonical len {len(cr)} id {id(cr)}\n')
