Incident Response Runbook

Incident Classification
- P0 (Critical): Data breach, auth bypass, platform outage
- P1 (High): Privilege escalation, lateral movement detected
- P2 (Medium): Anomalous activity, repeated auth failures
- P3 (Low): Policy violations, minor config drift

Escalation Procedure
1. Detection (alert, user report, monitoring)
2. Initial triage (SOC analyst, <15 min)
3. Escalate P0/P1 to Security Officer and on-call engineer
4. Containment (isolate affected systems)
5. Evidence preservation (logs, snapshots)
6. Root cause analysis
7. Remediation
8. Post-incident review (<48h)

Evidence Collection
- Export Prometheus metrics (last 7 days)
- Export audit logs (compliance/audit_trail.jsonl)
- Export compliance evidence via API `/api/v1/compliance/evidence/list`
- Screenshot affected dashboards

Communication
- Internal: Slack #security-incidents
- External: security@janusec.com
- Regulatory: 72h notification (GDPR), as applicable

