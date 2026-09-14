# Per-tenant SLOs

To visualize SLOs by tenant:

1. Use the new gauges (labels tenant_id):
   - janusec_slo_success_rate_tenant{tenant_id="<tenant>"}
   - janusec_guardrail_mttc_seconds_tenant{tenant_id="<tenant>"}

2. Example PromQL:

- Success rate below 95% for tenant t1 over 15m:
```
avg_over_time(janusec_slo_success_rate_tenant{tenant_id="t1"}[15m]) < 0.95
```

- MTTC above 2s for tenant t1 over 15m (EWMA approximated as gauge):
```
max_over_time(janusec_guardrail_mttc_seconds_tenant{tenant_id="t1"}[15m]) > 2
```

3. Create a dashboard panel per tenant or use a template variable for tenant_id.
