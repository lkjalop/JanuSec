# Grafana / Prometheus Query Examples for Forwarding & DecisionGate Telemetry

This document contains suggested Prometheus queries to visualize telemetry emitted by the forwarding
and decision endpoints. It assumes metrics are exposed in Prometheus format and scraped into Grafana.

- Total forward requests by persona (rate per minute):

```
rate(forward_requests_total[5m])
```

- Forward requests grouped by persona (instant):

```
sum by (persona) (forward_requests_total)
```

- Created decision gates from forwarding (count):

```
sum by (persona) (forward_created_decisions_total)
```

- Suggested actions produced (rate):

```
rate(forward_suggested_actions_total[5m])
```

- Decision lifecycle metrics:

```
sum(decision_created_total)
sum(decision_approved_total)
sum(decision_executed_total)
sum(decision_rolled_back_total)
```

- Decision approval rate (approvals / created) over 1h:

```
(sum(increase(decision_approved_total[1h])) / max(1, sum(increase(decision_created_total[1h])))) * 100
```

- Average time from creation to approval (requires audit-derived histogram; if you emit timestamps as gauges, use recorded timestamps)

Optional panel suggestions:
- Forwarding Overview: stacked bar by persona showing `forward_requests_total` and `forward_created_decisions_total`.
- Decision Gate Health: line charts for create/approve/execute/rollback rates and a single stat for current open pending decisions (derive from audit store via a small exporter).

Include these in your Grafana dashboard as Prometheus metrics panels. For production, add labels like `env` and `region` when registering counters.
